# 🛡️ FileGuard - Advanced Malware Detection System

**Author:** Mayur Nhavalde  
**Version:** 2.1.0  
**License:** MIT

A production-grade, enterprise-ready deep-learning pipeline for detecting malicious Windows PE (`.exe`) files with authentication, webhooks, reporting, and advanced caching.

---

## 🎯 Features

### Core Detection
- ✅ **Deep Learning Pipeline** – Autoencoder + ANN Classifier
- ✅ **PE Feature Extraction** – 50+ numeric features from PE headers
- ✅ **Threat Indicators** – 9 MITRE ATT&CK-tagged threat categories
- ✅ **Risk Scoring** – CRITICAL/HIGH/MEDIUM/LOW banding

### Enterprise Features
- 🔐 **JWT Authentication** – Secure token-based access
- 🔑 **API Key Management** – Programmatic access control
- 📊 **Persistent Database** – PostgreSQL scan history
- 🚀 **Async Task Queue** – Celery for background jobs
- 💾 **Redis Caching** – File deduplication & result caching
- 🔄 **Webhook Support** – Event-driven notifications
- 📈 **Advanced Reporting** – PDF/JSON export
- 🔍 **Rate Limiting** – Prevent abuse
- 📝 **Audit Logging** – Full request tracking

### API Features
- ✅ Single file scanning
- ✅ Batch scanning (up to 10 files)
- ✅ Scan history with pagination
- ✅ User profile management
- ✅ Admin statistics dashboard
- ✅ Webhook management
- ✅ Report generation

### UI Features
- ✅ Streamlit-based web interface
- ✅ Real-time scan results
- ✅ Threat indicator cards
- ✅ PE feature visualization
- ✅ Scan history tracking
- ✅ Analytics dashboard
- ✅ CSV/JSON export

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────┐
│         Nginx Reverse Proxy (SSL)                │
├────────────────────┬─────────────────────────────┤
│   Streamlit UI     │   FastAPI Backend           │
│  (port 8501)       │   (port 8000)               │
└────────────┬───────┴──────┬──────────────────────┘
             │              │
        ┌────▼──────┐   ┌───▼──────┐
        │ PostgreSQL │   │  Redis   │
        │ Database   │   │  Cache   │
        └────────────┘   └──────────┘
             ▲                │
             │            ┌───▼──────┐
             └────────────│ Celery   │
                          │ Worker   │
                          └──────────┘
```

---

## 🚀 Quick Start

### Development Setup

```bash
# Clone repository
git clone https://github.com/mayurOG/FileGuard.git
cd FileGuard

# Create environment file
cp .env.example .env

# Start services
docker-compose up --build

# Access services
# UI: http://localhost:8501
# API: http://localhost:8000/docs
# API Swagger: http://localhost:8000/docs
```

### Production Deployment

```bash
# Create secrets
cat > .env << EOF
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)
EOF

# Deploy
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose -f docker-compose.prod.yml exec fastapi alembic upgrade head
```

---

## 🔐 Authentication

### Register User
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user123",
    "email": "user@example.com",
    "password": "securepass123",
    "full_name": "User Name"
  }'
```

### Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user123",
    "password": "securepass123"
  }'
```

### Create API Key
```bash
curl -X POST http://localhost:8000/api-keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "My API Key"}'
```

---

## 📡 API Endpoints

### Authentication
- `POST /auth/register` – Register new user
- `POST /auth/login` – Login user
- `GET /users/me` – Get current user info

### Scanning
- `POST /predict` – Single file scan
- `POST /predict/batch` – Batch scan (max 10 files)
- `GET /scans/history` – Get scan history

### Webhooks
- `POST /webhooks` – Create webhook
- `GET /webhooks` – List webhooks

### Reports
- `POST /reports` – Generate report
- `GET /reports/{id}` – Get report

### Admin
- `GET /admin/stats` – System statistics

### Monitoring
- `GET /health` – Health check
- `GET /docs` – Swagger UI
- `GET /redoc` – ReDoc documentation

---

## 🐍 Python SDK

### Installation
```bash
pip install malware-detector-sdk
```

### Usage
```python
from malware_sdk import MalwareDetectorClient

# Initialize client
client = MalwareDetectorClient("http://localhost:8000")

# Register and login
token = client.register("user", "user@example.com", "pass", "User Name")

# Scan file
result = client.scan_file("malware.exe")
print(result["prediction"])  # "malicious" or "legitimate"
print(result["confidence"])  # 0.0 - 1.0
print(result["risk_level"])  # CRITICAL, HIGH, MEDIUM, LOW

# Batch scan
results = client.scan_batch(["file1.exe", "file2.exe"])
print(results["total"])  # Number of files

# Create webhook
webhook = client.create_webhook(
    "http://myserver.com/webhook",
    event_type="malware_detected"
)

# Generate report
report = client.create_report(
    "Weekly Report",
    "summary",
    "2024-01-01T00:00:00Z",
    "2024-01-07T23:59:59Z"
)

# View history
history = client.get_scan_history(skip=0, limit=10)
```

### CLI Usage
```bash
# Scan file
malware-detector scan malware.exe --url http://localhost:8000 --token <token>

# Batch scan
malware-detector batch file1.exe file2.exe file3.exe

# View history
malware-detector history --limit 20
```

---

## 🧪 Testing

```bash
# Run test suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=api --cov-report=html

# Specific test class
pytest tests/test_api.py::TestAuthentication -v
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@postgres:5432/malware_db

# Redis
REDIS_URL=redis://redis:6379/0

# Celery
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# Security
SECRET_KEY=your-secret-key
CORS_ORIGINS=http://localhost:8501,http://localhost:8000

# API
MAX_UPLOAD_SIZE=104857600  # 100MB
RATE_LIMIT_REQUESTS=30
RATE_LIMIT_WINDOW=60
```

---

## 📊 Threat Indicators

| Indicator | Severity | MITRE |
|-----------|----------|-------|
| High section entropy | HIGH/CRITICAL | T1027 |
| No static imports | HIGH | T1027.001 |
| High ordinal imports | MEDIUM | T1036 |
| Missing PE checksum | MEDIUM | T1036.005 |
| No version info | LOW | T1036 |
| High export count | MEDIUM | T1574.001 |
| High resource entropy | HIGH | T1027 |
| Tiny code section | HIGH | T1055 |
| Unusual subsystem | MEDIUM | T1014 |

---

## 📈 Performance

- **Single File Scan:** ~0.4-0.8s
- **Batch (10 files):** ~4-8s
- **Model Loading:** ~30s startup
- **Cache Hit Rate:** 95%+ for repeated scans
- **Concurrent Requests:** 100+ with rate limiting

---

## 🐳 Docker Images

All images available on Docker Hub:

```bash
# Pull images
docker pull mayurOG/fileguard-api:latest
docker pull mayurOG/fileguard-ui:latest
docker pull mayurOG/fileguard-celery:latest
```

---

## 📝 Database Schema

### Users
- id, username, email, hashed_password, full_name, is_active, is_admin, created_at

### Scans
- id, user_id, filename, file_hash, file_size, prediction, confidence, risk_level, pe_features, threat_indicators, scan_time, created_at

### Webhooks
- id, user_id, url, event_type, is_active, secret_key, created_at

### Reports
- id, user_id, name, report_type, start_date, end_date, total_scans, malicious_count, data, file_path, created_at

### API Keys
- id, user_id, key, name, is_active, last_used, created_at, expires_at

---

## 🚢 Deployment

### Docker Hub
```bash
docker build -t mayurOG/fileguard-api:2.1.0 ./api
docker push mayurOG/fileguard-api:2.1.0
```

### Kubernetes
```bash
kubectl apply -f k8s/
```

### AWS ECS/Fargate
```bash
# Push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker tag fileguard-api:latest <account>.dkr.ecr.<region>.amazonaws.com/fileguard-api:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/fileguard-api:latest
```

---

## 🔒 Security Best Practices

- ✅ Use HTTPS/SSL in production
- ✅ Rotate secrets regularly
- ✅ Enable rate limiting
- ✅ Use strong database passwords
- ✅ Enable audit logging
- ✅ Regularly update dependencies
- ✅ Use API keys instead of credentials
- ✅ Implement IP whitelisting
- ✅ Enable CORS selectively

---

## 📄 API Response Example

```json
{
  "filename": "sample.exe",
  "sha256": "949b6765d794c53656c9afc45b90d9a2cfcae6bb30444086b29225f19242217b",
  "prediction": "malicious",
  "confidence": 0.95,
  "risk_level": "HIGH",
  "time_taken_sec": 0.417,
  "threat_indicators": [
    {
      "name": "High Section Entropy",
      "description": "Max section entropy is 7.2. This indicates packing or encryption.",
      "severity": "HIGH",
      "mitre": "T1027 – Obfuscated Files or Information"
    }
  ],
  "pe_features": {
    "SectionsMeanEntropy": 5.2,
    "SectionsMaxEntropy": 7.2,
    "ImportsNb": 86,
    "ExportNb": 0
  }
}
```

---

## 📚 Documentation

- [API Documentation](http://localhost:8000/docs)
- [Architecture Guide](./docs/ARCHITECTURE.md)
- [Deployment Guide](./docs/DEPLOYMENT.md)
- [Contributing Guide](./CONTRIBUTING.md)

---

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## 📞 Support

- Issues: https://github.com/mayurOG/FileGuard/issues
- Email: mayur.nhavalde@gmail.com

---

## 📜 License

MIT License - see LICENSE file for details

---

## 👨‍💻 Author

**Mayur Nhavalde**
- GitHub: [@mayurOG](https://github.com/mayurOG)
- Email: mayur.nhavalde@gmail.com

---

**Made with ❤️ for cybersecurity professionals**
