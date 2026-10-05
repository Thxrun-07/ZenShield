"""Database configuration and session management for ZenShield.

Provides:
- SQLAlchemy engine & session factory
- Zero import-time side-effects
- Idempotent default IOC seeding
- Safe migration from legacy SQLite ioc.db stores
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from zenshield.core.config import settings
from zenshield.db.models import Base, IOCRecord

logger = logging.getLogger("zenshield.audit")

# Build SQLAlchemy engine based on configuration
db_url = settings.DATABASE_URL
engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_default_iocs(db: Session) -> None:
    """Populates initial known malicious indicators if not already registered."""
    default_iocs = [
        ("evil-example.com", "domain", "community", "critical", 90.0, "Known credential harvester domain"),
        ("phishing-bank-update.test", "domain", "internal", "high", 80.0, "Financial phishing campaign"),
        ("http://known-malware-drop.test/payload.exe", "url", "abuse_ch", "critical", 95.0, "Known malware payload"),
        ("crypto-airdrop-scam.test", "domain", "community", "high", 75.0, "Fraudulent crypto drainer campaign"),
    ]

    for indicator, ind_type, threat_cat, severity, conf, desc in default_iocs:
        existing = db.query(IOCRecord).filter(IOCRecord.indicator_value == indicator).first()
        if not existing:
            rec = IOCRecord(
                indicator_value=indicator,
                raw_value=indicator,
                indicator_type=ind_type,
                threat_category=threat_cat,
                threat_level=severity,
                confidence_score=conf,
                report_count=1,
                notes=desc,
                status="active",
            )
            db.add(rec)
    db.commit()


def migrate_legacy_ioc_db(legacy_path: str, db: Session) -> int:
    """
    Safely migrates existing records from legacy SQLite ioc.db into unified threat_iocs table.
    Returns count of migrated rows.
    """
    p = Path(legacy_path)
    if not p.is_file():
        return 0

    migrated_count = 0
    try:
        conn = sqlite3.connect(legacy_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='iocs'")
        if not cursor.fetchone():
            conn.close()
            return 0

        cursor.execute("SELECT indicator, indicator_type, source, severity, description FROM iocs")
        rows = cursor.fetchall()

        for row in rows:
            val = row["indicator"]
            existing = db.query(IOCRecord).filter(IOCRecord.indicator_value == val).first()
            if not existing:
                rec = IOCRecord(
                    indicator_value=val,
                    raw_value=val,
                    indicator_type=row["indicator_type"] or "domain",
                    threat_category=row["source"] or "legacy_migration",
                    threat_level=row["severity"] or "high",
                    confidence_score=80.0,
                    report_count=1,
                    notes=row["description"],
                    status="active",
                )
                db.add(rec)
                migrated_count += 1
        db.commit()
        conn.close()
        if migrated_count > 0:
            logger.info("Migrated %d legacy IOC records from %s into unified database.", migrated_count, legacy_path)
    except Exception as e:
        logger.warning("Could not migrate legacy ioc.db at %s: %s", legacy_path, e)

    return migrated_count


def init_db() -> None:
    """
    Creates database tables and seeds initial data.
    Called explicitly during application lifespan.
    """
    # Ensure directory exists for sqlite
    if settings.DATABASE_PATH and not settings.DATABASE_PATH.startswith(":memory:"):
        Path(settings.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_default_iocs(db)
        # Attempt to migrate legacy ioc.db if found
        legacy_path = str(Path(settings.DATABASE_PATH).parent / "ioc.db")
        if legacy_path != settings.DATABASE_PATH:
            migrate_legacy_ioc_db(legacy_path, db)
