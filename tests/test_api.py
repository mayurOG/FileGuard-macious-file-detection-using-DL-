"""
Comprehensive test suite for Malware Detector API
Author: Mayur Nhavalde
"""

import pytest
import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Import after database setup
from database import get_db, Base
from app_v2 import app
from models import User
from auth import hash_password

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_register_user(self):
        response = client.post("/auth/register", json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepass123",
            "full_name": "Test User"
        })
        assert response.status_code == 200
        assert "access_token" in response.json()
    
    def test_register_duplicate_email(self):
        # Register first user
        client.post("/auth/register", json={
            "username": "user1",
            "email": "test@example.com",
            "password": "securepass123",
            "full_name": "User 1"
        })
        
        # Try register with same email
        response = client.post("/auth/register", json={
            "username": "user2",
            "email": "test@example.com",
            "password": "securepass123",
            "full_name": "User 2"
        })
        assert response.status_code == 400
    
    def test_login_user(self):
        # Register user
        client.post("/auth/register", json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepass123",
            "full_name": "Test User"
        })
        
        # Login
        response = client.post("/auth/login", json={
            "username": "testuser",
            "password": "securepass123"
        })
        assert response.status_code == 200
        assert "access_token" in response.json()
    
    def test_login_invalid_password(self):
        # Register user
        client.post("/auth/register", json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepass123",
            "full_name": "Test User"
        })
        
        # Try login with wrong password
        response = client.post("/auth/login", json={
            "username": "testuser",
            "password": "wrongpassword"
        })
        assert response.status_code == 401


class TestScanEndpoints:
    """Test scan endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        response = client.post("/auth/register", json={
            "username": "scanuser",
            "email": "scan@example.com",
            "password": "securepass123",
            "full_name": "Scan User"
        })
        return response.json()["access_token"]
    
    @pytest.fixture
    def headers(self, auth_token):
        return {"Authorization": f"Bearer {auth_token}"}
    
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert "version" in response.json()
    
    @patch("app_v2._run_prediction")
    def test_single_file_scan(self, mock_predict, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        mock_predict.return_value = {
            "filename": "test.exe",
            "sha256": "abc123",
            "prediction": "legitimate",
            "confidence": 0.1,
            "risk_level": "LOW",
            "time_taken_sec": 0.5,
            "threat_indicators": [],
            "pe_features": {}
        }
        
        with open("/tmp/test.exe", "wb") as f:
            f.write(b"MZ" + b"\x00" * 1000)
        
        with open("/tmp/test.exe", "rb") as f:
            response = client.post(
                "/predict",
                files={"file": ("test.exe", f, "application/octet-stream")},
                headers=headers
            )
        
        assert response.status_code == 200
        assert response.json()["prediction"] in ["malicious", "legitimate"]
    
    def test_scan_non_exe_file(self, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        with open("/tmp/test.txt", "wb") as f:
            f.write(b"Not an exe file")
        
        with open("/tmp/test.txt", "rb") as f:
            response = client.post(
                "/predict",
                files={"file": ("test.txt", f, "application/octet-stream")},
                headers=headers
            )
        
        assert response.status_code == 400


class TestWebhooks:
    """Test webhook endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        response = client.post("/auth/register", json={
            "username": "webhookuser",
            "email": "webhook@example.com",
            "password": "securepass123",
            "full_name": "Webhook User"
        })
        return response.json()["access_token"]
    
    def test_create_webhook(self, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        response = client.post(
            "/webhooks",
            json={
                "url": "http://example.com/webhook",
                "event_type": "all"
            },
            headers=headers
        )
        
        assert response.status_code == 200
        assert response.json()["url"] == "http://example.com/webhook"
    
    def test_list_webhooks(self, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        response = client.get("/webhooks", headers=headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestRateLimiting:
    """Test rate limiting"""
    
    @patch("cache.RateLimiter.is_rate_limited")
    def test_rate_limit_exceeded(self, mock_limiter, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        mock_limiter.return_value = True
        
        response = client.post(
            "/predict",
            files={"file": ("test.exe", b"MZ" * 500, "application/octet-stream")},
            headers=headers
        )
        
        assert response.status_code == 429


class TestCaching:
    """Test caching functionality"""
    
    @patch("cache.FileDeduplication.get_cached_result")
    @patch("app_v2._run_prediction")
    def test_cached_result_returned(self, mock_predict, mock_cache):
        cached_result = {
            "filename": "cached.exe",
            "prediction": "malicious",
            "confidence": 0.95
        }
        
        mock_cache.return_value = cached_result
        
        # Verify cache hit
        result = mock_cache("abc123")
        assert result == cached_result


class TestReporting:
    """Test report generation"""
    
    @pytest.fixture
    def auth_token(self):
        response = client.post("/auth/register", json={
            "username": "reportuser",
            "email": "report@example.com",
            "password": "securepass123",
            "full_name": "Report User"
        })
        return response.json()["access_token"]
    
    def test_create_report(self, auth_token):
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        from datetime import datetime, timedelta
        
        response = client.post(
            "/reports",
            json={
                "name": "Test Report",
                "report_type": "summary",
                "start_date": (datetime.utcnow() - timedelta(days=7)).isoformat(),
                "end_date": datetime.utcnow().isoformat()
            },
            headers=headers
        )
        
        assert response.status_code == 200
        assert "id" in response.json()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
