"""
Database Configuration for the Intelligence Module.

Provides SQLAlchemy engine, session maker, base model, and initialization.
Uses SQLite by default so that it is self-contained and zero-configuration.
Can also share sessions if passed from external integration.
"""

from __future__ import annotations

import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = os.getenv("INTELLIGENCE_DATABASE_URL", "sqlite:///./redflag_intelligence.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SQLAlchemy database session.
    Closes the session after request completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Creates tables for the intelligence module if they do not exist.
    Safe to call multiple times.
    """
    # Import models here to ensure they are registered with Base metadata
    from app.intelligence import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
