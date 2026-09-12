"""
FastAPI backend for Malicious PE File Detection
Author: Mayur Nhavalde
Features:
  - Single file prediction
  - Batch file scanning
  - Detailed PE feature analysis with threat indicators
  - Health check endpoint
  - Rate limiting (slowapi)
  - Structured JSON logging
  - Async background-safe temp file handling
"""

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import numpy as np
import tempfile
import time
import logging
import json
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import List
from concurrent.futures import ThreadPoolExecutor

from Final_Testing import extract_infos, compute_threat_indicators
from tensorflow.keras.models import load_model, Model

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

# ── Rate limiter ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ── Model loading ─────────────────────────────────────────────────────────────
logger.info("Loading models...")
autoencoder = load_model("auto_model.keras")
ann_model   = load_model("maliNN_model.keras")
encoder_model = Model(
    inputs=autoencoder.input,
    outputs=autoencoder.get_layer("bottleneck").output
)
logger.info("Models loaded successfully.")

# Thread pool for CPU-bound PE parsing (keeps async loop free)
_executor = ThreadPoolExecutor(max_workers=4)

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Malicious PE File Detector API",
    description="Deep-learning-based PE file malware detection with advanced analysis.",
    version="2.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_prediction(file_bytes: bytes, filename: str) -> dict:
    """CPU-bound analysis — runs in thread pool."""
    start = time.time()

    # Write to temp file
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    tmp.write(file_bytes)
    tmp_path = tmp.name
    tmp.close()

    try:
        features = extract_infos(tmp_path)
        threat_indicators = compute_threat_indicators(features)

        feature_array = np.array([list(features.values())], dtype=np.float32)
        bottleneck     = encoder_model.predict(feature_array, verbose=0)
        raw_score      = float(ann_model.predict(bottleneck, verbose=0)[0][0])

        # Risk level banding
        if raw_score >= 0.85:
            risk_level = "CRITICAL"
        elif raw_score >= 0.65:
            risk_level = "HIGH"
        elif raw_score >= 0.50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        prediction = "malicious" if raw_score > 0.5 else "legitimate"
        duration   = round(time.time() - start, 3)

        logger.info(json.dumps({
            "event": "prediction",
            "filename": filename,
            "prediction": prediction,
            "confidence": round(raw_score, 4),
            "risk_level": risk_level,
            "duration_sec": duration,
        }))

        return {
            "filename": filename,
            "sha256": _sha256(file_bytes),
            "prediction": prediction,
            "confidence": round(raw_score, 4),
            "risk_level": risk_level,
            "time_taken_sec": duration,
            "threat_indicators": threat_indicators,
            "pe_features": {k: round(float(v), 4) if isinstance(v, float) else int(v)
                            for k, v in features.items()},
        }
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Monitoring"])
async def health():
    """Liveness probe — returns service status and model info."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models": {
            "autoencoder": "auto_model.keras",
            "classifier":  "maliNN_model.keras",
        },
    }


@app.post("/predict", tags=["Detection"])
@limiter.limit("30/minute")
async def predict(request: Request, file: UploadFile = File(...)):
    """
    Scan a single PE (.exe) file.
    Returns prediction, confidence, risk level, threat indicators, and full PE features.
    """
    if not file.filename.lower().endswith(".exe"):
        raise HTTPException(status_code=400, detail="Only .exe files are accepted.")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        _executor, _run_prediction, file_bytes, file.filename
    )

    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])

    return result


@app.post("/predict/batch", tags=["Detection"])
@limiter.limit("10/minute")
async def predict_batch(request: Request, files: List[UploadFile] = File(...)):
    """
    Scan up to 10 PE files in one request.
    Returns a list of results (one per file).
    """
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch request.")

    loop = asyncio.get_event_loop()
    tasks = []
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

    return {"total": len(results), "results": results}


@app.get("/stats", tags=["Monitoring"])
async def stats():
    """
    Returns basic API stats placeholder.
    Extend with a Redis/SQLite backend for persistent counters.
    """
    return {
        "message": "Stats endpoint ready. Connect a persistent store for full metrics.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
