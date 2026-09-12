# PE Malicious File Detector using ML &DL

**Author:** Mayur Nhavalde

A production-grade deep-learning pipeline for detecting malicious Windows PE (`.exe`) files.  
Built with **FastAPI**, **TensorFlow**, and **Streamlit**, containerised with **Docker Compose**.

---

## Architecture

```
┌─────────────────────┐        HTTP/REST        ┌──────────────────────┐
│   Streamlit UI      │ ─────────────────────►  │  FastAPI Backend     │
│  (port 8501)        │                          │  (port 8000)         │
│                     │ ◄─────────────────────── │                      │
└─────────────────────┘   JSON results           └──────────────────────┘
                                                         │
                                              ┌──────────▼──────────┐
                                              │  DL Pipeline        │
                                              │  Autoencoder ──►    │
                                              │  ANN Classifier     │
                                              └─────────────────────┘
```

## Features

### API (FastAPI)
| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness probe |
| `/predict` | POST | Single-file scan |
| `/predict/batch` | POST | Batch scan (up to 10 files) |
| `/stats` | GET | Stats placeholder |
| `/docs` | GET | Swagger UI |

- **Rate limiting** – 30 req/min per IP on `/predict`, 10/min on batch
- **Structured JSON logging** – every prediction logged with metadata
- **SHA-256 hashing** – each file fingerprinted in the response
- **Risk level banding** – CRITICAL / HIGH / MEDIUM / LOW
- **MITRE ATT&CK–tagged threat indicators** – 10 heuristic checks

### UI (Streamlit)
- 🔍 **Single Scan** – full result card with confidence bar, threat indicators, PE feature charts
- 📦 **Batch Scan** – scan up to 10 files at once, summary metrics
- 📋 **Scan History** – session-persistent table with CSV/JSON export
- 📈 **Analytics** – confidence distribution, risk breakdown, malicious-over-time chart
- API health indicator in the sidebar

---

## Quick Start

### Prerequisites
- Docker & Docker Compose installed

### Run

```bash
cd Malicious_File_Detection_using_DL-main
docker compose up --build
```

- UI → http://localhost:8501  
- API docs → http://localhost:8000/docs

---

## Model Pipeline

1. **Feature Extraction** (`Final_Testing.py`)  
   Parses PE headers, sections, imports, exports, resources using `pefile`.  
   Returns ~55 numeric features.

2. **Autoencoder** (`auto_model.keras`)  
   Compresses features into a bottleneck representation.

3. **ANN Classifier** (`maliNN_model.keras`)  
   Predicts malicious probability (0–1).

---

## Threat Indicators

| Indicator | Severity | MITRE |
|---|---|---|
| High section entropy | HIGH/CRITICAL | T1027 |
| No static imports | HIGH | T1027.001 |
| High ordinal import ratio | MEDIUM | T1036 |
| Missing PE checksum | MEDIUM | T1036.005 |
| No version information | LOW | T1036 |
| High export count | MEDIUM | T1574.001 |
| High resource entropy | HIGH | T1027 |
| Tiny code section | HIGH | T1055 |
| Non-standard subsystem | MEDIUM | T1014 |

---

## Project Structure

```
├── api/
│   ├── app.py              # FastAPI application
│   ├── Final_Testing.py    # PE feature extraction + threat indicators
│   ├── auto_model.keras    # Autoencoder model
│   ├── maliNN_model.keras  # ANN classifier model
│   ├── requirements.txt
│   └── Dockerfile
├── ui/
│   ├── streamlit_app.py    # Streamlit UI
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```
