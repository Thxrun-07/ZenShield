from fastapi import APIRouter, HTTPException, status
from schemas.verification import PhishingReportRequest

router = APIRouter(prefix="/report", tags=["Community Reporting"])


@router.post("/phishing", summary="Submit a Phishing or Fraud Report")
async def submit_report(report: PhishingReportRequest):
    """
    Endpoint for users to submit fraud reports (phishing URLs, suspicious SMS messages, etc.).
    """
    if not report.target_url and not report.message_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report must contain either a target_url or message_content."
        )

    # In production, this can persist to a database or append to feedback queues for retraining
    return {
        "status": "received",
        "message": "Phishing report successfully submitted for review.",
        "category": report.category
    }
