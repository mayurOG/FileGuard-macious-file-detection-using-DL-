# Architecture Documentation

**Author:** Mayur Nhavalde  
**Version:** 2.1.0

Comprehensive architecture documentation for FileGuard system.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet/Users                            │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
        ┌────────────────────────────────────┐
        │   Nginx Reverse Proxy (SSL)         │
        │   - Load balancing                  │
        │   - Rate limiting                   │
        │   - Request routing                 │
        └───┬───────────────────┬─────────────┘
            │                   │
    ┌───────▼────────┐  ┌──────▼─────────┐
    │  Streamlit UI  │  │  FastAPI API   │
    │ (port 8501)    │  │ (port 8000)    │
    │                │  │                │
    │ - Web UI       │  │ - Authentication
    │ - File upload  │  │ - Scanning
    │ - Analytics    │  │ - Webhooks
    │ - Reporting    │  │ - Reports
    └────────┬───────┘  └────────┬────────┘
             │                   │
             └───────────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    ┌───▼─────┐  ┌──────▼──────┐  ┌──────▼───┐
    │PostgreSQL│  │    Redis    │  │  Celery  │
    │ Database │  │    Cache    │  │  Worker  │
    │          │  │             │  │          │
    │ - Users  │  │ - Sessions  │  │ - Tasks  │
    │ - Scans  │  │ - Cache     │  │ - Events │
    │ - Reports│  │ - Rate limit│  │ - Jobs   │
    └──────────┘  └─────────────┘  └──────────┘
```

---

## Components

### 1. Frontend (Streamlit UI)

**Location:** `./ui/streamlit_app.py`

**Responsibilities:**
- User interface
- File upload
- Result display
- History tracking
- Analytics
- Export functionality

**Technologies:**
- Streamlit 1.35.0
- Pandas 2.2.2
- Plotly for charts
- Session state management

**Key Features:**
- Single/batch file scanning
- Threat indicator visualization
- PE feature breakdown
- Scan history with filters
- CSV/JSON export
- Real-time analysis

---

### 2. Backend API (FastAPI)

**Location:** `./api/app_v2.py`

**Responsibilities:**
- Authentication
- Request handling
- Scan processing
- Database operations
- Webhook management
- Report generation

**Technologies:**
- FastAPI 0.111.0
- Uvicorn (ASGI server)
- Gunicorn (production)
- SQLAlchemy ORM
- Pydantic validation

**Endpoints:**
- `/auth/*` - Authentication
- `/predict` - Single scan
- `/predict/batch` - Batch scan
- `/scans/history` - History
- `/webhooks` - Webhooks
- `/reports` - Reports
- `/admin/stats` - Statistics

---

### 3. Machine Learning Pipeline

**Location:** `./api/Final_Testing.py`

**Responsibilities:**
- PE header parsing
- Feature extraction
- Threat indicator generation
- Model inference

**Models:**
- Autoencoder: Feature compression
- ANN Classifier: Malware prediction

**Features Extracted:**
- ~50 numeric PE features
- Section entropy
- Import/Export analysis
- Resource information
- Version info

**Threat Indicators:** (9 types)
- High entropy sections
- Missing imports
- Ordinal imports
- Missing checksum
- No version info
- High exports
- Resource entropy
- Tiny code section
- Unusual subsystem

---

### 4. Database (PostgreSQL)

**Location:** `./api/models.py`

**Tables:**
- `users` - User accounts
- `api_keys` - API access keys
- `scans` - Scan results
- `webhooks` - Webhook subscriptions
- `webhook_logs` - Delivery logs
- `reports` - Generated reports

**Relationships:**
```
Users ──┬──> Scans
        ├──> API Keys
        ├──> Webhooks ──> Webhook Logs
        └──> Reports
```

**Indexing:**
- `idx_scan_user_date` - Fast user history
- `idx_scan_file_hash` - Deduplication
- `idx_webhook_user` - Webhook lookup

---

### 5. Caching Layer (Redis)

**Location:** `./api/cache.py`

**Purposes:**
- Result caching (30 days default)
- Rate limiting tracking
- Session storage
- Temporary data

**Patterns:**
- `scan_result:<file_hash>` - Cached predictions
- `rate_limit:<user_id>` - Request counts
- `session:<session_id>` - User sessions

---

### 6. Task Queue (Celery)

**Location:** `./api/tasks.py`

**Tasks:**
- `send_webhook` - Async webhook delivery (max 3 retries)
- `generate_report` - PDF report generation
- `cleanup_old_scans` - Periodic cleanup (90+ days)

**Configuration:**
- Broker: Redis
- Result Backend: Redis
- Workers: 4 concurrent tasks
- Task time limit: 30 minutes

---

### 7. Authentication Module

**Location:** `./api/auth.py`

**Features:**
- Password hashing (bcrypt)
- JWT token generation
- Token verification
- API key generation
- Role-based access (admin)

**Security:**
- HS256 algorithm
- 60-minute token expiry
- Secure password storage
- API key rotation support

---

### 8. Python SDK

**Location:** `./sdk/malware_sdk.py`

**Purpose:**
- Programmatic API access
- CLI tool for scanning
- Integration with external systems

**Methods:**
- `scan_file()` - Single scan
- `scan_batch()` - Batch scan
- `create_webhook()` - Subscribe to events
- `create_report()` - Generate reports
- `get_scan_history()` - Query history

---

## Data Flow

### Scan Request Flow

```
1. User uploads file → UI
2. UI sends to API /predict
3. API validates authentication
4. API checks rate limits
5. API checks cache
6. If cached: return cached result
7. If not cached:
   a. Write file to temp location
   b. Extract PE features
   c. Compute threat indicators
   d. Run ML models (Autoencoder + ANN)
   e. Generate risk score
   f. Save to database
   g. Cache result (30 days)
   h. Trigger webhooks (async)
   i. Return result
8. UI displays results
```

### Webhook Event Flow

```
1. Scan completes
2. Check webhook subscriptions
3. For each matching webhook:
   a. Enqueue webhook task (Celery)
   b. Worker retrieves task
   c. Sign payload with HMAC-SHA256
   d. POST to webhook URL
   e. Retry up to 3 times on failure
   f. Log delivery status
```

### Report Generation Flow

```
1. User requests report
2. Check date range
3. Query scans from database
4. Calculate statistics
5. Enqueue report task (Celery)
6. Worker:
   a. Gather scan data
   b. Create PDF with ReportLab
   c. Save to filesystem
   d. Update database
7. Return report reference
8. User downloads report
```

---

## Security Architecture

### Authentication Layers

```
1. Public Endpoints (Health, Docs)
   └─ No auth required

2. API Endpoints
   ├─ JWT Token Required
   └─ Or API Key Required

3. Admin Endpoints
   ├─ JWT Token Required
   ├─ User must be admin
   └─ Rate limited: 10/min

4. Webhook Endpoints
   ├─ HMAC-SHA256 signature
   └─ Secret key validation
```

### Data Protection

- Passwords: bcrypt with salt
- API keys: hashed storage, plaintext return once
- Tokens: HS256 signed, 60-min expiry
- File uploads: Temp storage, auto-cleanup
- Database: Encryption at rest (configurable)
- Transit: HTTPS/TLS enforcement

### Rate Limiting

- API: 30 req/min per user
- Batch: 10 req/min per user
- Admin: 10 req/min per user
- Webhooks: 5 retries with exponential backoff

---

## Performance Architecture

### Caching Strategy

```
Request → Cache Hit (95%)
           └─ Return cached result (instant)
         
         → Cache Miss (5%)
           └─ PE Extraction (0.1s)
           └─ Feature Computation (0.2s)
           └─ Model Inference (0.1s)
           └─ DB Save (0.05s)
           └─ Cache Result (0.05s)
           └─ Total: ~0.5s
```

### Async Processing

- Webhooks: Non-blocking, queued
- Reports: Background generation
- Cleanup: Scheduled tasks
- Benefits: Faster API responses, better UX

### Database Indexing

- User + Date: Fast history queries
- File hash: Fast deduplication lookup
- User ID: Fast webhook queries

---

## Scalability Considerations

### Horizontal Scaling

```
Load Balancer
    ├─ API Instance 1
    ├─ API Instance 2
    ├─ API Instance 3
    └─ API Instance N
         │
         └─ PostgreSQL (Primary + Replicas)
         └─ Redis Cluster
         └─ Celery Workers (Auto-scale)
```

### Bottlenecks & Solutions

| Component | Bottleneck | Solution |
|-----------|-----------|----------|
| API | Single process | Gunicorn workers |
| Database | Single connection | Connection pooling |
| Cache | Single Redis | Cluster mode |
| Tasks | Limited workers | Add workers |
| ML | CPU-bound | GPU acceleration |

### Capacity Planning

- **Single Instance:** ~100 concurrent users
- **3 Instances:** ~300 concurrent users
- **10 Instances:** ~1000+ concurrent users

With proper tuning and infrastructure:
- ~10,000 scans/day
- ~50ms average latency
- 99.9% uptime

---

## Monitoring & Observability

### Metrics

- API response time
- Cache hit rate
- Database query time
- Queue depth
- Error rate
- Webhook delivery success

### Logging

- All requests logged (JSON format)
- Database queries logged (dev mode)
- Task execution logged
- Error stack traces captured

### Health Checks

- API: `/health` endpoint
- Database: Connection test
- Redis: PING command
- Celery: Worker heartbeat

---

## Technology Stack

### Backend
- **Framework:** FastAPI
- **Server:** Uvicorn/Gunicorn
- **ORM:** SQLAlchemy
- **Validation:** Pydantic
- **Auth:** JWT + bcrypt

### Database
- **Primary:** PostgreSQL 15
- **Cache:** Redis 7
- **Connection Pooling:** SQLAlchemy NullPool

### Machine Learning
- **Framework:** TensorFlow 2.16
- **Models:** Keras (.keras format)
- **Feature Extraction:** pefile

### Async Processing
- **Queue:** Celery
- **Broker:** Redis
- **Result Backend:** Redis

### Frontend
- **Framework:** Streamlit 1.35
- **Visualization:** Plotly
- **Data Handling:** Pandas

### Infrastructure
- **Containerization:** Docker
- **Orchestration:** Docker Compose / Kubernetes
- **Reverse Proxy:** Nginx
- **SSL/TLS:** Let's Encrypt / Self-signed

### CI/CD
- **Version Control:** Git/GitHub
- **CI/CD:** GitHub Actions
- **Registry:** Docker Hub

---

## Development Architecture

### Project Structure

```
FileGuard/
├── api/                    # FastAPI backend
│   ├── app_v2.py          # Enhanced app
│   ├── models.py          # Database models
│   ├── schemas.py         # Pydantic schemas
│   ├── database.py        # DB configuration
│   ├── auth.py            # Authentication
│   ├── cache.py           # Caching/Rate limit
│   ├── tasks.py           # Celery tasks
│   ├── Final_Testing.py   # ML pipeline
│   ├── requirements.txt
│   └── Dockerfile*
├── ui/                     # Streamlit frontend
│   ├── streamlit_app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .streamlit/
├── sdk/                    # Python SDK
│   ├── malware_sdk.py
│   ├── __init__.py
│   └── setup.py
├── tests/                  # Test suite
│   └── test_api.py
├── docs/                   # Documentation
├── docker-compose.yml      # Dev environment
├── docker-compose.prod.yml # Prod environment
├── nginx.conf             # Nginx config
└── .github/
    └── workflows/
        └── ci-cd.yml      # GitHub Actions
```

### Dependency Graph

```
Models.py
    ├─ Database models

Schemas.py
    ├─ Request/Response validation

Auth.py
    ├─ Authentication utilities
    └─ Models.User

Cache.py
    ├─ Redis caching
    └─ Rate limiting

Tasks.py
    ├─ Celery tasks
    ├─ Database.SessionLocal
    └─ Models.*

App_v2.py
    ├─ Models
    ├─ Schemas
    ├─ Auth
    ├─ Cache
    ├─ Tasks
    ├─ Database
    └─ Final_Testing (ML)
```

---

## Future Enhancements

- [ ] GPU acceleration for inference
- [ ] Multi-model ensemble
- [ ] Behavioral analysis
- [ ] Sandboxed execution
- [ ] Real-time threat feed integration
- [ ] Advanced analytics/ML
- [ ] Mobile app
- [ ] On-premise deployment options

---

**Version:** 2.1.0  
**Last Updated:** 2024  
**Author:** Mayur Nhavalde
