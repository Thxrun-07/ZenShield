"""Local SQLite-backed IOC and reputation provider.

Provides persistent indicator lookup without requiring external network calls or API keys.
Supports indicator types: 'domain' and 'url'.
"""

from pathlib import Path
import sqlite3
from typing import List, Optional

from zenshield.config import settings
from zenshield.models.schemas import IOCRecord, NormalizedURL, SignalSeverity
from zenshield.services.reputation.base import BaseReputationProvider, ReputationResult


class SQLiteReputationProvider(BaseReputationProvider):
    """Local SQLite implementation of reputation and IOC checking."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DATABASE_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._conn is None:
                self._conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
            return self._conn

        db_file = Path(self.db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist, and seed default IOCs."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT UNIQUE NOT NULL,
                    indicator_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(indicator_type);"
            )
            conn.commit()

        # Seed initial indicators if empty
        self._seed_default_iocs()

    def _seed_default_iocs(self) -> None:
        """Populate initial known malicious indicators if database is empty."""
        initial_iocs = [
            (
                "evil-example.com",
                "domain",
                "community",
                "critical",
                "Known credential harvester domain",
            ),
            (
                "phishing-bank-update.test",
                "domain",
                "internal",
                "high",
                "Financial phishing campaign targeting banking customers",
            ),
            (
                "http://known-malware-drop.test/payload.exe",
                "url",
                "abuse_ch",
                "critical",
                "Known malware payload download link",
            ),
            (
                "crypto-airdrop-scam.test",
                "domain",
                "community",
                "high",
                "Fraudulent crypto drainer campaign",
            ),
        ]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM iocs")
            count = cursor.fetchone()[0]
            if count == 0:
                cursor.executemany(
                    """
                    INSERT OR IGNORE INTO iocs (indicator, indicator_type, source, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    initial_iocs,
                )
                conn.commit()

    def add_ioc(
        self,
        indicator: str,
        indicator_type: str,
        source: str = "community",
        severity: str = "high",
        description: Optional[str] = None,
    ) -> bool:
        """Insert or replace an indicator record in the SQLite database."""
        clean_indicator = indicator.strip().lower()
        clean_type = indicator_type.strip().lower()
        clean_severity = severity.strip().lower()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO iocs (indicator, indicator_type, source, severity, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (clean_indicator, clean_type, source, clean_severity, description),
            )
            conn.commit()
            return cursor.rowcount > 0

    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        """Check URL and domain against local IOC database."""
        if not norm_url.is_valid:
            return ReputationResult(is_known_ioc=False)

        candidates = [
            (norm_url.original_url.lower(), "url"),
            (norm_url.normalized_url.lower(), "url"),
        ]

        # Add domain hierarchy candidates (e.g. sub.domain.com, domain.com)
        if norm_url.hostname:
            host_parts = norm_url.hostname.lower().split(".")
            for i in range(len(host_parts)):
                parent_domain = ".".join(host_parts[i:])
                if parent_domain and (parent_domain, "domain") not in candidates:
                    candidates.append((parent_domain, "domain"))

        if norm_url.registered_domain and (norm_url.registered_domain.lower(), "domain") not in candidates:
            candidates.append((norm_url.registered_domain.lower(), "domain"))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cand_val, cand_type in candidates:
                if not cand_val:
                    continue
                cursor.execute(
                    """
                    SELECT indicator, indicator_type, source, severity, description
                    FROM iocs
                    WHERE indicator = ?
                    LIMIT 1
                    """,
                    (cand_val,),
                )
                row = cursor.fetchone()
                if row:
                    try:
                        sev = SignalSeverity(row["severity"].lower())
                    except ValueError:
                        sev = SignalSeverity.HIGH

                    return ReputationResult(
                        is_known_ioc=True,
                        indicator=row["indicator"],
                        indicator_type=row["indicator_type"],
                        source=row["source"],
                        severity=sev,
                        description=row["description"],
                    )

        return ReputationResult(is_known_ioc=False)

    def list_iocs(self, limit: int = 100) -> List[IOCRecord]:
        """List IOCs in the database for auditing and diagnostics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, indicator, indicator_type, source, severity, description, created_at
                FROM iocs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                IOCRecord(
                    id=r["id"],
                    indicator=r["indicator"],
                    indicator_type=r["indicator_type"],
                    source=r["source"],
                    severity=r["severity"],
                    description=r["description"],
                    created_at=str(r["created_at"]),
                )
                for r in rows
            ]
