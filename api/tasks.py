"""
Celery tasks for async processing
Author: Mayur Nhavalde
"""

import os
from celery import Celery
import requests
import hmac
import hashlib
import json
from datetime import datetime

# Celery configuration
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

celery_app = Celery(
    "malware_detector",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes hard limit
)


@celery_app.task(bind=True, max_retries=3)
def send_webhook(self, webhook_id: int, scan_data: dict, secret_key: str):
    """Send webhook notification for scan completion"""
    try:
        from database import SessionLocal
        from models import Webhook, WebhookLog
        
        db = SessionLocal()
        webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
        
        if not webhook:
            return {"status": "error", "message": "Webhook not found"}
        
        # Create signed payload
        payload = json.dumps(scan_data).encode()
        signature = hmac.new(
            secret_key.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        headers = {
            "X-Webhook-Signature": signature,
            "Content-Type": "application/json",
        }
        
        response = requests.post(
            webhook.url,
            json=scan_data,
            headers=headers,
            timeout=10
        )
        
        # Log webhook delivery
        log = WebhookLog(
            webhook_id=webhook_id,
            scan_id=scan_data.get("scan_id"),
            status_code=response.status_code,
            response=response.text[:500]
        )
        db.add(log)
        db.commit()
        db.close()
        
        return {"status": "success", "status_code": response.status_code}
        
    except requests.exceptions.RequestException as exc:
        db.close()
        raise self.retry(exc=exc, countdown=60)


@celery_app.task
def generate_report(user_id: int, report_id: int):
    """Generate comprehensive scan report"""
    try:
        from database import SessionLocal
        from models import Report, Scan
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        import os
        
        db = SessionLocal()
        report = db.query(Report).filter(Report.id == report_id).first()
        scans = db.query(Scan).filter(
            Scan.user_id == user_id,
            Scan.created_at >= report.start_date,
            Scan.created_at <= report.end_date
        ).all()
        
        # Generate PDF report
        os.makedirs("/tmp/reports", exist_ok=True)
        file_path = f"/tmp/reports/report_{report_id}.pdf"
        
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph(f"<b>Malware Detection Report - {report.name}</b>", styles['Heading1'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Summary table
        data = [
            ["Metric", "Value"],
            ["Total Scans", str(report.total_scans)],
            ["Malicious", str(report.malicious_count)],
            ["Legitimate", str(report.total_scans - report.malicious_count)],
            ["Detection Rate", f"{(report.malicious_count/report.total_scans*100):.2f}%"],
        ]
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        
        report.file_path = file_path
        db.commit()
        db.close()
        
        return {"status": "success", "file_path": file_path}
        
    except Exception as e:
        db.close()
        return {"status": "error", "message": str(e)}


@celery_app.task
def cleanup_old_scans(days: int = 90):
    """Clean up scans older than specified days"""
    try:
        from database import SessionLocal
        from models import Scan
        from datetime import datetime, timedelta
        
        db = SessionLocal()
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        deleted = db.query(Scan).filter(Scan.created_at < cutoff_date).delete()
        db.commit()
        db.close()
        
        return {"status": "success", "deleted_count": deleted}
        
    except Exception as e:
        db.close()
        return {"status": "error", "message": str(e)}
