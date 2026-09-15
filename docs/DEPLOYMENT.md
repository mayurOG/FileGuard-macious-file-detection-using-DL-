# Deployment Guide

**Author:** Mayur Nhavalde  
**Last Updated:** 2024

This guide covers deploying FileGuard to various environments.

---

## Table of Contents

1. [Local Development](#local-development)
2. [Docker Hub Deployment](#docker-hub-deployment)
3. [Production with SSL](#production-with-ssl)
4. [Cloud Platforms](#cloud-platforms)
5. [Kubernetes](#kubernetes)
6. [Troubleshooting](#troubleshooting)

---

## Local Development

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Git

### Quick Start

```bash
# Clone repository
git clone https://github.com/mayurOG/FileGuard-macious-file-detection-using-DL-.git
cd FileGuard-macious-file-detection-using-DL-

# Copy environment file
cp .env.example .env

# Start services
docker-compose up --build

# Initialize database
docker-compose exec fastapi python -c "from database import init_db; init_db()"

# Access services
# UI: http://localhost:8501
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Development Workflow

```bash
# View logs
docker-compose logs -f fastapi

# Run tests
docker-compose exec fastapi pytest tests/ -v

# Access database
docker-compose exec postgres psql -U malware_user -d malware_db

# Stop services
docker-compose down
```

---

## Docker Hub Deployment

### Prerequisites
- Docker Hub account
- Local Docker installation

### Build and Push

```bash
# Login to Docker Hub
docker login

# Build API image
docker build -f api/Dockerfile.prod -t mayurOG/fileguard-api:2.1.0 ./api
docker build -f api/Dockerfile.prod -t mayurOG/fileguard-api:latest ./api

# Build UI image
docker build -f ui/Dockerfile -t mayurOG/fileguard-ui:2.1.0 ./ui
docker build -f ui/Dockerfile -t mayurOG/fileguard-ui:latest ./ui

# Build Celery image
docker build -f api/Dockerfile.celery -t mayurOG/fileguard-celery:2.1.0 ./api
docker build -f api/Dockerfile.celery -t mayurOG/fileguard-celery:latest ./api

# Push to Docker Hub
docker push mayurOG/fileguard-api:2.1.0
docker push mayurOG/fileguard-api:latest
docker push mayurOG/fileguard-ui:2.1.0
docker push mayurOG/fileguard-ui:latest
docker push mayurOG/fileguard-celery:2.1.0
docker push mayurOG/fileguard-celery:latest
```

### Deploy from Docker Hub

```bash
# Create environment file
cat > .env << 'EOF'
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)
EOF

# Update docker-compose.prod.yml to use Docker Hub images
# Change: build: to image:

# Pull and start services
docker pull mayurOG/fileguard-api:latest
docker pull mayurOG/fileguard-ui:latest
docker pull mayurOG/fileguard-celery:latest

docker-compose -f docker-compose.prod.yml up -d
```

---

## Production with SSL

### Prerequisites
- Domain name
- SSL certificate (or use Let's Encrypt)

### Setup SSL

```bash
# Create SSL directory
mkdir -p ssl

# Option 1: Use Let's Encrypt with Certbot
docker run -it --rm \
  -v $(pwd)/ssl:/etc/letsencrypt \
  -v $(pwd)/.well-known:/var/www/certbot \
  certbot/certbot certonly --standalone \
  -d yourdomain.com

# Copy certificates
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ssl/key.pem

# Option 2: Self-signed certificate (for testing)
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout ssl/key.pem \
  -out ssl/cert.pem
```

### Deploy with SSL

```bash
# Create .env
cat > .env << 'EOF'
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)
DOMAIN=yourdomain.com
EOF

# Update nginx.conf with your domain
sed -i 's/server_name _;/server_name yourdomain.com;/' nginx.conf

# Start services
docker-compose -f docker-compose.prod.yml up -d nginx

# Verify SSL
curl -k https://yourdomain.com/health
```

### Auto-renew SSL

```bash
# Create renewal script
cat > renew-ssl.sh << 'EOF'
#!/bin/bash
docker run -it --rm \
  -v $(pwd)/ssl:/etc/letsencrypt \
  -v $(pwd)/.well-known:/var/www/certbot \
  certbot/certbot renew

docker-compose -f docker-compose.prod.yml restart nginx
EOF

# Add to crontab (monthly renewal)
(crontab -l; echo "0 2 1 * * /app/renew-ssl.sh") | crontab -
```

---

## Cloud Platforms

### AWS ECS/Fargate

```bash
# Create ECR repositories
aws ecr create-repository --repository-name fileguard-api
aws ecr create-repository --repository-name fileguard-ui

# Login to ECR
aws ecr get-login-password | docker login \
  --username AWS \
  --password-stdin $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com

# Tag and push images
docker tag fileguard-api:latest $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com/fileguard-api:latest
docker push $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com/fileguard-api:latest

# Similar for UI and Celery images

# Create RDS PostgreSQL
aws rds create-db-instance \
  --db-instance-identifier fileguard-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username malware_user \
  --master-user-password $(openssl rand -hex 16)

# Create ElastiCache Redis
aws elasticache create-cache-cluster \
  --cache-cluster-id fileguard-redis \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --num-cache-nodes 1
```

### Google Cloud Run

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT_ID/fileguard-api ./api

# Deploy API
gcloud run deploy fileguard-api \
  --image gcr.io/PROJECT_ID/fileguard-api \
  --platform managed \
  --region us-central1 \
  --memory 2Gi \
  --set-env-vars DATABASE_URL=$DATABASE_URL,REDIS_URL=$REDIS_URL

# Deploy UI
gcloud run deploy fileguard-ui \
  --image gcr.io/PROJECT_ID/fileguard-ui \
  --platform managed \
  --region us-central1 \
  --set-env-vars API_URL=$API_URL
```

### Azure Container Instances

```bash
# Login to Azure
az login

# Create resource group
az group create --name fileguard-rg --location eastus

# Build and push to ACR
az acr build --registry fileguardacr \
  --image fileguard-api:latest ./api

# Deploy with docker-compose
az container create \
  --resource-group fileguard-rg \
  --name fileguard \
  --image fileguardacr.azurecr.io/fileguard-api:latest \
  --registry-login-server fileguardacr.azurecr.io \
  --registry-username $USER \
  --registry-password $PASSWORD
```

---

## Kubernetes

### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- Helm (optional)

### Deploy with Kubernetes

```bash
# Create namespace
kubectl create namespace fileguard

# Create secrets
kubectl create secret generic fileguard-secrets \
  --from-literal=secret-key=$(openssl rand -hex 32) \
  --from-literal=db-password=$(openssl rand -hex 16) \
  -n fileguard

# Create ConfigMap for environment
kubectl create configmap fileguard-config \
  --from-literal=DATABASE_URL=postgresql://... \
  -n fileguard

# Apply manifests
kubectl apply -f k8s/postgres-deployment.yaml -n fileguard
kubectl apply -f k8s/redis-deployment.yaml -n fileguard
kubectl apply -f k8s/api-deployment.yaml -n fileguard
kubectl apply -f k8s/celery-deployment.yaml -n fileguard
kubectl apply -f k8s/ui-deployment.yaml -n fileguard

# Verify deployment
kubectl get pods -n fileguard
kubectl logs -f deployment/fileguard-api -n fileguard
```

### Example Deployment

```yaml
# k8s/api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fileguard-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fileguard-api
  template:
    metadata:
      labels:
        app: fileguard-api
    spec:
      containers:
      - name: api
        image: mayurOG/fileguard-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: fileguard-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            configMapKeyRef:
              name: fileguard-config
              key: redis-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
```

---

## Monitoring & Logging

### Setup Prometheus

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'fileguard-api'
    static_configs:
      - targets: ['localhost:8000']
```

### Setup ELK Stack

```bash
# Start ELK
docker-compose -f docker-compose.elk.yml up

# Configure Filebeat
filebeat.inputs:
- type: container
  paths:
    - '/var/lib/docker/containers/*/*.log'

output.elasticsearch:
  hosts: ["localhost:9200"]
```

---

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL
docker-compose logs postgres

# Verify connection
docker-compose exec postgres psql -U malware_user -d malware_db -c "SELECT 1"

# Rebuild database
docker-compose down -v
docker-compose up
```

### Redis Issues

```bash
# Check Redis
docker-compose logs redis

# Test connection
docker-compose exec redis redis-cli ping

# Clear cache
docker-compose exec redis redis-cli FLUSHALL
```

### API Not Starting

```bash
# Check API logs
docker-compose logs fastapi

# Verify models exist
docker-compose exec fastapi ls -la *.keras

# Check dependencies
docker-compose exec fastapi pip list
```

### Permission Issues

```bash
# Fix file permissions
sudo chown -R $USER:$USER .

# Rebuild images
docker-compose build --no-cache
```

---

## Performance Tuning

### Database Optimization

```sql
-- Create indexes
CREATE INDEX idx_scan_user_date ON scans(user_id, created_at);
CREATE INDEX idx_scan_file_hash ON scans(file_hash);
CREATE INDEX idx_webhook_user ON webhooks(user_id);

-- Analyze
VACUUM ANALYZE;
```

### Redis Optimization

```bash
# Increase max memory
docker-compose exec redis redis-cli CONFIG SET maxmemory 1gb
docker-compose exec redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### API Tuning

```python
# Increase workers
gunicorn --workers 8 --worker-class uvicorn.workers.UvicornWorker app:app

# Enable compression
compression_middleware = GZipMiddleware(app, minimum_size=1000)
```

---

## Maintenance

### Backup Database

```bash
# Backup
docker-compose exec postgres pg_dump -U malware_user malware_db > backup.sql

# Restore
docker-compose exec -T postgres psql -U malware_user malware_db < backup.sql
```

### Update Images

```bash
# Pull latest
docker-compose pull

# Restart
docker-compose up -d
```

### Health Checks

```bash
# API
curl -s http://localhost:8000/health | jq .

# UI
curl -s http://localhost:8501/_stcore/health

# Database
docker-compose exec postgres pg_isready
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/mayurOG/FileGuard-macious-file-detection-using-DL-/issues
- Email: mayur.nhavalde@gmail.com

---

**Last Updated:** 2024  
**Version:** 2.1.0
