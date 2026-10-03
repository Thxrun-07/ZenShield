from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any, Literal


class VerifyRequest(BaseModel):
    """
    Request model for unified verification endpoint (/api/v1/verify).
    Enforces strict string validation and upper length bounds.
    """
    type: Literal["url", "message"] = Field(
        ..., 
        description="Type of verification request: 'url' or 'message'"
    )
    content: str = Field(
        ..., 
        min_length=1,
        max_length=10000,
        description="Content string to verify (must not be empty or blank, max 10,000 characters)"
    )

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Content must not be empty or whitespace only.")
        return v.strip()


class URLVerificationRequest(BaseModel):
    """
    Request payload for URL verification.
    """
    url: str = Field(
        ..., 
        min_length=1, 
        max_length=2048, 
        description="Target URL to be verified (max 2048 characters)"
    )

    @field_validator("url")
    @classmethod
    def validate_url_string(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty.")
        return clean


class MessageVerificationRequest(BaseModel):
    """
    Request payload for SMS or message verification.
    """
    message_body: str = Field(
        ..., 
        min_length=1, 
        max_length=10000, 
        description="Message body text (max 10,000 characters)"
    )
    sender: Optional[str] = Field(
        None, 
        max_length=256, 
        description="Sender information (max 256 characters)"
    )

    @field_validator("message_body")
    @classmethod
    def validate_message_body(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Message body cannot be empty.")
        return clean


class RiskResult(BaseModel):
    """
    Normalized result schema returned by teammate detection engines.
    """
    is_risky: bool = Field(..., description="Whether phishing or malicious content was detected")
    risk_score: float = Field(..., description="Normalized risk score (e.g. 0.0 to 1.0)")
    risk_level: Literal["low", "medium", "high"] = Field(..., description="Categorical risk classification")
    reasons: List[str] = Field(default_factory=list, description="List of reasons or evidence flags")


class VerifyResponse(BaseModel):
    """
    Unified verification response returned to the frontend.
    """
    type: Literal["url", "message"] = Field(..., description="Verification type processed")
    content: str = Field(..., description="The content string that was verified")
    result: RiskResult = Field(..., description="Normalized detection result")


class QRScanResponse(BaseModel):
    """
    Response schema for QR scanning endpoint (/api/v1/qr/scan).
    """
    decoded: bool = Field(..., description="Whether a QR code was successfully detected and decoded")
    payload: Optional[str] = Field(None, description="Decoded string content from the QR code")
    payload_type: Optional[Literal["url", "text"]] = Field(None, description="Type of payload: 'url' or 'text'")
    risk_analysis: Optional[Dict[str, Any]] = Field(None, description="Risk analysis result if payload is a URL")


class OCRAnalyzeResponse(BaseModel):
    """
    Response schema for OCR analysis endpoint (/api/v1/ocr/analyze).
    """
    success: bool = Field(..., description="Indicates whether OCR text extraction succeeded in reading text")
    extracted_text: str = Field(default="", description="Text extracted from image via OCR")
    risk_analysis: Optional[Dict[str, Any]] = Field(None, description="Risk analysis from MessageAdapter if text was detected")
    message: Optional[str] = Field(None, description="Informational message when no text is detected")


class PhishingReportRequest(BaseModel):
    """
    Payload for user-submitted phishing reports.
    """
    target_url: Optional[str] = Field(None, max_length=2048, description="Reported phishing URL")
    message_content: Optional[str] = Field(None, max_length=10000, description="Reported message text")
    category: str = Field(..., max_length=64, description="Report type, e.g., 'url', 'sms', 'email', 'qr'")
    description: Optional[str] = Field(None, max_length=2000, description="User comments or observations regarding the threat")
