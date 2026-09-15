"""
FastAPI backend for Malicious PE File Detection - Enhanced Version
Author: Mayur Nhavalde
Features:
  - JWT authentication
  - Database persistence
  - Async task queue (Celery)
  - Redis caching & rate limiting
  - Webhook support
  - Advanced reporting
  - API key management
"""

from fastapi import FastAPI, UploadFile, File, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthCredentials
import os
import numpy as np
import tempfile
import time
import logging
import json
import hashlib
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session

from Final_Testing import extract_infos, compute_threat_indicators
from tensorflow.keras.models import load_model, Model
from database import SessionLocal, get_db, init_db
from models import User, Scan, Webhook, APIKey
from schemas import (
    UserCreate, UserLogin, Token, UserResponse, ScanResponse,
    BatchScanResponse, WebhookCreate, WebhookResponse, ReportRequest,
    ReportResponse, StatsResponse
)
from auth import (
    hash_password, verify_password, create_access_token,
    verify_access_token, generate_api_key, get_current_user,
    get_current_admin_user
)
from cache import RedisCache, RateLimiter, FileDeduplication
from tasks import celery_app, send_webhook, generate_report

# ── Logging ─────────────────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger = logging.getLogger("malware_api")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# ── Model loading ─────────────────────────────────────────────────────────────
logger.info("Loading models...")
autoencoder = load_model("auto_model.keras")
ann_model   = load_model("maliNN_model.keras")
encoder_model = Model(
    inputs=autoencoder.input,
    outputs=autoencoder.get_layer("bottleneck").output
)
logger.info("Models loaded successfully.")

# Thread pool for CPU-bound PE parsing
_executor = ThreadPoolExecutor(max_workers=4)

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Malicious PE File Detector API v2",
    description="Enterprise-grade PE file malware detection with auth, caching, webhooks.",
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup/Shutdown ──────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    logger.info("Database initialized")


# ── Authentication routes ──────────────────────────────────────────────────────
@app.post("/auth/register", response_model=Token, tags=["Auth"])
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register new user"""
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pwd = hash_password(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        full_name=user_data.full_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    access_token = create_access_token({"sub": str(db_user.id)})
    return {
        "access_token": access_token,
        "expires_in": 3600
    }


@app.post("/auth/login", response_model=Token, tags=["Auth"])
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login user"""
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": str(user.id)})
    return {
        "access_token": access_token,
        "expires_in": 3600
    }


# ── User routes ────────────────────────────────────────────────────────────────
@app.get("/users/me", response_model=UserResponse, tags=["Users"])
async def get_current_user_info(user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user info"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ── API Key routes ────────────────────────────────────────────────────────────
@app.post("/api-keys", tags=["API Keys"])
async def create_api_key(
    request_data: dict,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create API key for programmatic access"""
    api_key = generate_api_key()
    hashed_key = hash_password(api_key)
    
    db_key = APIKey(
        user_id=user_id,
        key=hashed_key,
        name=request_data.get("name", "API Key")
    )
    db.add(db_key)
    db.commit()
    
    return {
        "key": api_key,
        "message": "Save this key securely. You won't be able to see it again."
    }


# ── Scan routes ────────────────────────────────────────────────────────────────
def _run_prediction(file_bytes: bytes, filename: str) -> dict:
    """CPU-bound analysis — runs in thread pool."""
    start = time.time()

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    tmp.write(file_bytes)
    tmp_path = tmp.name
    tmp.close()

    try:
        # Check cache for duplicate files
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        cached = FileDeduplication.get_cached_result(file_hash)
        if cached:
            return cached
        
        try:
            features = extract_infos(tmp_path)
        except Exception as e:
            return {"error": f"PE parsing failed: {str(e)[:100]}"}
        
        threat_indicators = compute_threat_indicators(features)
        feature_array = np.array([list(features.values())], dtype=np.float32)
        bottleneck = encoder_model.predict(feature_array, verbose=0)
        raw_score = float(ann_model.predict(bottleneck, verbose=0)[0][0])

        if raw_score >= 0.85:
            risk_level = "CRITICAL"
        elif raw_score >= 0.65:
            risk_level = "HIGH"
        elif raw_score >= 0.50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        prediction = "malicious" if raw_score > 0.5 else "legitimate"
        duration = round(time.time() - start, 3)

        result = {
            "filename": filename,
            "sha256": file_hash,
            "prediction": prediction,
            "confidence": round(raw_score, 4),
            "risk_level": risk_level,
            "time_taken_sec": duration,
            "threat_indicators": threat_indicators,
            "pe_features": {k: round(float(v), 4) if isinstance(v, float) else int(v)
                            for k, v in features.items()},
        }
        
        # Cache result
        FileDeduplication.cache_result(file_hash, result)
        
        logger.info(json.dumps({
            "event": "prediction",
            "filename": filename,
            "prediction": prediction,
            "confidence": round(raw_score, 4),
            "risk_level": risk_level,
            "duration_sec": duration,
        }))
        
        return result
        
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@app.post("/predict", response_model=ScanResponse, tags=["Detection"])
async def predict(
    request: Request,
    file: UploadFile = File(...),
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Scan single PE file"""
    if not file.filename.lower().endswith(".exe"):
        raise HTTPException(status_code=400, detail="Only .exe files are accepted.")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Check rate limit
    if RateLimiter.is_rate_limited(f"user:{user_id}", 30, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _run_prediction, file_bytes, file.filename)

    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])

    # Store scan in database
    scan = Scan(
        user_id=user_id,
        filename=file.filename,
        file_hash=result["sha256"],
        file_size=len(file_bytes),
        prediction=result["prediction"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        pe_features=result["pe_features"],
        threat_indicators=result["threat_indicators"],
        scan_time=result["time_taken_sec"]
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Trigger webhooks
    webhooks = db.query(Webhook).filter(
        (Webhook.user_id == user_id) &
        (Webhook.is_active == True) &
        ((Webhook.event_type == "all") |
         ((Webhook.event_type == "scan_complete")) |
         ((Webhook.event_type == "malware_detected") & (result["prediction"] == "malicious")))
    ).all()
    
    for webhook in webhooks:
        send_webhook.delay(webhook.id, {**result, "scan_id": scan.id}, webhook.secret_key)

    return result


@app.post("/predict/batch", response_model=BatchScanResponse, tags=["Detection"])
async def predict_batch(
    request: Request,
    files: List[UploadFile] = File(...),
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Scan batch of PE files"""
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch request.")

    loop = asyncio.get_event_loop()
    tasks = []
    file_count = len(files)
    
    for f in files:
        if not f.filename.lower().endswith(".exe"):
            tasks.append({"filename": f.filename, "error": "Not an .exe file — skipped."})
            continue
        fb = await f.read()
        if len(fb) == 0:
            tasks.append({"filename": f.filename, "error": "Empty file — skipped."})
            continue
        tasks.append(loop.run_in_executor(_executor, _run_prediction, fb, f.filename))

    results = []
    for t in tasks:
        if isinstance(t, dict):
            results.append(t)
        else:
            r = await t
            results.append(r)

    return {"total": file_count, "results": results}


# ── History routes ────────────────────────────────────────────────────────────
@app.get("/scans/history", tags=["History"])
async def get_scan_history(
    skip: int = 0,
    limit: int = 10,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's scan history"""
    scans = db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    total = db.query(Scan).filter(Scan.user_id == user_id).count()
    
    return {
        "total": total,
        "scans": scans,
        "page": skip // limit + 1,
        "page_size": limit
    }


# ── Webhook routes ────────────────────────────────────────────────────────────
@app.post("/webhooks", response_model=WebhookResponse, tags=["Webhooks"])
async def create_webhook(
    webhook_data: WebhookCreate,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create webhook subscription"""
    secret = generate_api_key()
    
    webhook = Webhook(
        user_id=user_id,
        url=webhook_data.url,
        event_type=webhook_data.event_type,
        secret_key=secret
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    
    return webhook


@app.get("/webhooks", tags=["Webhooks"])
async def list_webhooks(
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user's webhooks"""
    webhooks = db.query(Webhook).filter(Webhook.user_id == user_id).all()
    return webhooks


# ── Report routes ────────────────────────────────────────────────────────────
@app.post("/reports", response_model=dict, tags=["Reports"])
async def create_report(
    report_data: ReportRequest,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate scan report"""
    scans = db.query(Scan).filter(
        (Scan.user_id == user_id) &
        (Scan.created_at >= report_data.start_date) &
        (Scan.created_at <= report_data.end_date)
    ).all()
    
    malicious_count = sum(1 for s in scans if s.prediction == "malicious")
    
    report = Report(
        user_id=user_id,
        name=report_data.name,
        report_type=report_data.report_type,
        start_date=report_data.start_date,
        end_date=report_data.end_date,
        total_scans=len(scans),
        malicious_count=malicious_count,
        data={"scans": [s.to_dict() for s in scans]}
    )
    db.add(report)
    db.commit()
    
    # Trigger async report generation
    generate_report.delay(user_id, report.id)
    
    return {"id": report.id, "status": "generating"}


# ── Admin stats routes ────────────────────────────────────────────────────────
@app.get("/admin/stats", response_model=StatsResponse, tags=["Admin"])
async def get_stats(
    user_id: int = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get system statistics (admin only)"""
    total_scans = db.query(Scan).count()
    total_users = db.query(User).count()
    malicious = db.query(Scan).filter(Scan.prediction == "malicious").count()
    legitimate = total_scans - malicious
    avg_confidence = db.query(Scan).with_entities(Scan.confidence).all()
    avg_conf = sum(c[0] for c in avg_confidence) / len(avg_confidence) if avg_confidence else 0
    
    return {
        "total_scans": total_scans,
        "total_users": total_users,
        "malicious_detected": malicious,
        "legitimate_detected": legitimate,
        "avg_confidence": avg_conf,
        "top_threats": []
    }


# ── Health routes ────────────────────────────────────────────────────────────
@app.get("/health", tags=["Monitoring"])
async def health():
    """Health check"""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.1.0",
        "models": {
            "autoencoder": "auto_model.keras",
            "classifier": "maliNN_model.keras",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
