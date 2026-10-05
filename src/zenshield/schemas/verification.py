"""Unified verification request and response schemas."""

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from zenshield.schemas.risk import RiskResult


class VerifyRequest(BaseModel):
    """Unified verification request payload for POST /api/v1/verify."""

    type: Literal["url", "message"] = Field(
        ...,
        description="Type of verification request: 'url' or 'message'",
    )
    content: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Content string to verify (max 10,000 characters)",
    )

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Content must not be empty or whitespace only.")
        return v.strip()


class URLVerificationRequest(BaseModel):
    """Direct URL verification request."""

    url: str = Field(..., min_length=1, max_length=2048, description="Target URL")

    @field_validator("url")
    @classmethod
    def validate_url_string(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty.")
        return clean


class MessageVerificationRequest(BaseModel):
    """Direct message verification request."""

    message_body: str = Field(..., min_length=1, max_length=10000, description="Message text")
    sender: str | None = Field(None, max_length=256, description="Sender header/id")

    @field_validator("message_body")
    @classmethod
    def validate_message_body(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Message body cannot be empty.")
        return clean


class VerifyResponse(BaseModel):
    """
    Unified verification response returned by POST /api/v1/verify.
    Preserves zero-leakage: `content` returns sanitized/masked content for privacy.
    """

    type: Literal["url", "message"] = Field(..., description="Verification type processed")
    content: str = Field(..., description="Sanitized/masked representation of verified content")
    result: RiskResult = Field(..., description="Unified risk assessment")


class QRScanResponse(BaseModel):
    """Response schema for QR scanning endpoint (/api/v1/qr/scan)."""

    decoded: bool = Field(..., description="Whether a QR code was successfully decoded")
    payload: str | None = Field(None, description="Decoded string payload")
    payload_type: Literal["url", "text"] | None = Field(None, description="Payload type: 'url' or 'text'")
    risk_analysis: dict[str, Any] | None = Field(None, description="Risk analysis result if payload is a URL")


class OCRAnalyzeResponse(BaseModel):
    """Response schema for OCR endpoint (/api/v1/ocr/analyze)."""

    success: bool = Field(..., description="Whether text was successfully extracted")
    extracted_text: str = Field(default="", description="Sanitized extracted text")
    risk_analysis: dict[str, Any] | None = Field(None, description="Risk analysis if text was detected")
    message: str | None = Field(None, description="Informational message when no text is detected")


class PhishingReportRequest(BaseModel):
    """Payload for user-submitted phishing reports (/api/v1/report/phishing)."""

    target_url: str | None = Field(None, max_length=2048, description="Reported phishing URL")
    message_content: str | None = Field(None, max_length=10000, description="Reported message text")
    category: str = Field(..., max_length=64, description="Report type: 'url', 'sms', 'email', 'qr'")
    description: str | None = Field(None, max_length=2000, description="User comments/evidence")
