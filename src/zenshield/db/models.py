"""SQLAlchemy Models for ZenShield Unified Threat Intelligence & IOC Storage.

Defines schemas for:
- IOCRecord: Canonical Threat Intelligence indicators (URL, domain, phone, UPI, email, etc.)
- Report: Community Fraud reports associated with IOCs
- CommunityReport: Resident fraud reports with privacy-masked narratives
- ReportConfirmation: Resident confirmations / upvotes
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


class IOCRecord(Base):
    """
    Threat Intelligence Indicator of Compromise (IOC).
    Stores canonical normalized indicators and their aggregate reputation metrics.
    """

    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    indicator_value = Column(String(500), unique=True, index=True, nullable=False)
    raw_value = Column(String(500), nullable=True)
    indicator_type = Column(String(50), index=True, nullable=False)
    threat_category = Column(String(100), index=True, nullable=True, default="phishing")
    threat_level = Column(String(50), default="medium")  # low, medium, high, critical
    confidence_score = Column(Float, default=50.0)  # 0.0 to 100.0
    report_count = Column(Integer, default=1)
    confirmation_count = Column(Integer, default=0)
    status = Column(String(50), default="active")  # active, under_review, verified_malicious, resolved
    first_seen_at = Column(DateTime(timezone=True), default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    notes = Column(Text, nullable=True)

    # Relationships
    reports = relationship("CommunityReport", back_populates="ioc", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<IOCRecord(id={self.id}, value='{self.indicator_value}', type='{self.indicator_type}')>"


class Report(Base):
    """
    Community Fraud Report table.
    """

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(String(100), nullable=False, default="phishing")
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    location = Column(String(150), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    ioc = relationship("IOCRecord", backref="submitted_reports")

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, ioc_id={self.ioc_id}, report_type='{self.report_type}')>"


class CommunityReport(Base):
    """
    Resident-submitted community fraud incident report.
    Stores privacy-masked description, regional context, and financial impact.
    """

    __tablename__ = "community_reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id", ondelete="SET NULL"), nullable=True, index=True)
    indicator_value = Column(String(500), index=True, nullable=False)
    indicator_type = Column(String(50), index=True, nullable=False)
    title = Column(String(250), nullable=False)
    description = Column(Text, nullable=False)  # Privacy-masked text
    raw_description_had_pii = Column(Boolean, default=False)
    region = Column(String(100), index=True, nullable=False, default="National")
    fraud_category = Column(String(100), index=True, nullable=False, default="phishing")
    amount_lost = Column(Float, nullable=True)  # INR lost if victim was defrauded
    confirmation_count = Column(Integer, default=0)
    status = Column(String(50), default="active")  # active, verified, rejected, resolved
    incident_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    ioc = relationship("IOCRecord", back_populates="reports")
    confirmations = relationship("ReportConfirmation", back_populates="report", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<CommunityReport(id={self.id}, title='{self.title}', region='{self.region}')>"


class ReportConfirmation(Base):
    """
    Community confirmation / upvote for an existing report.
    """

    __tablename__ = "report_confirmations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    comment = Column(Text, nullable=True)
    region = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    report = relationship("CommunityReport", back_populates="confirmations")

    def __repr__(self) -> str:
        return f"<ReportConfirmation(id={self.id}, report_id={self.report_id})>"
