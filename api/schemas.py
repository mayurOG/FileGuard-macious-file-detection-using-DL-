"""
Pydantic schemas for request/response validation
Author: Mayur Nhavalde
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# User schemas
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Scan schemas
class ThreatIndicator(BaseModel):
    name: str
    description: str
    severity: str
    mitre: str


class ScanRequest(BaseModel):
    filename: str


class ScanResponse(BaseModel):
    id: Optional[int]
    filename: str
    sha256: str
    prediction: str
    confidence: float
    risk_level: str
    time_taken_sec: float
    threat_indicators: List[ThreatIndicator]
    pe_features: Dict[str, Any]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class BatchScanResponse(BaseModel):
    total: int
    results: List[ScanResponse]


class ScanHistory(BaseModel):
    total: int
    scans: List[ScanResponse]
    page: int
    page_size: int


# Webhook schemas
class WebhookCreate(BaseModel):
    url: str
    event_type: str = Field(..., pattern="^(scan_complete|malware_detected|all)$")


class WebhookResponse(BaseModel):
    id: int
    url: str
    event_type: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Report schemas
class ReportRequest(BaseModel):
    name: str
    report_type: str = Field(..., pattern="^(summary|detailed|comparison)$")
    start_date: datetime
    end_date: datetime


class ReportResponse(BaseModel):
    id: int
    name: str
    report_type: str
    total_scans: int
    malicious_count: int
    created_at: datetime

    class Config:
        from_attributes = True


# API Key schemas
class APIKeyCreate(BaseModel):
    name: str


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Stats schemas
class StatsResponse(BaseModel):
    total_scans: int
    total_users: int
    malicious_detected: int
    legitimate_detected: int
    avg_confidence: float
    top_threats: List[Dict[str, Any]]
