"""
Database Models for Malware Detection System
Author: Mayur Nhavalde
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(255))
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans = relationship("Scan", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")


class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    key = Column(String(100), unique=True, index=True)
    name = Column(String(100))
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="api_keys")


class Scan(Base):
    """Scan result model"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String(255))
    file_hash = Column(String(64), unique=True, index=True)
    file_size = Column(Integer)
    prediction = Column(String(20))  # malicious or legitimate
    confidence = Column(Float)
    risk_level = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    pe_features = Column(JSON)
    threat_indicators = Column(JSON)
    scan_time = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="scans")
    webhooks = relationship("WebhookLog", back_populates="scan")


class Webhook(Base):
    """Webhook subscriptions for notifications"""
    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    url = Column(String(500))
    event_type = Column(String(50))  # scan_complete, malware_detected
    is_active = Column(Boolean, default=True)
    secret_key = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    logs = relationship("WebhookLog", back_populates="webhook")


class WebhookLog(Base):
    """Webhook delivery logs"""
    __tablename__ = "webhook_logs"

    id = Column(Integer, primary_key=True, index=True)
    webhook_id = Column(Integer, ForeignKey("webhooks.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"))
    status_code = Column(Integer)
    response = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    webhook = relationship("Webhook", back_populates="logs")
    scan = relationship("Scan", back_populates="webhooks")


class Report(Base):
    """Generated reports"""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String(255))
    report_type = Column(String(50))  # summary, detailed, comparison
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    total_scans = Column(Integer)
    malicious_count = Column(Integer)
    data = Column(JSON)
    file_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
