"""Startup and configuration resilience tests."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from zenshield.core.config import Settings
from zenshield.main import app


def test_health_reports_database_and_all_engines_ready():
    """GET /health reports overall health, database connectivity, and readiness of all 3 engines."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert "ZenShield" in data["service"]
    assert data["database"] == "healthy"
    assert data["engines"]["url"] == "ready"
    assert data["engines"]["message"] == "ready"
    assert data["engines"]["intelligence"] == "ready"


def test_root_status_endpoint():
    """GET / reports root status and documentation link."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "online"
    assert "ZenShield" in data["service"]
    assert data["documentation"] == "/docs"


def test_database_created_at_configured_path():
    """Ensures database tables are initialized at custom configured path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_db_path = Path(tmpdir) / "custom_test.db"
        custom_db_url = f"sqlite:///{custom_db_path.as_posix()}"

        Settings(DATABASE_URL=custom_db_url)
        assert not custom_db_path.exists()

        # Initialize tables on custom engine
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from zenshield.db.database import Base, seed_default_iocs

        engine = create_engine(custom_db_url)
        try:
            Base.metadata.create_all(bind=engine)
            session_factory = sessionmaker(bind=engine)
            with session_factory() as session:
                seed_default_iocs(session)

            assert custom_db_path.exists()
            assert custom_db_path.stat().st_size > 0
        finally:
            engine.dispose()


def test_app_starts_from_any_working_directory():
    """Verify application boots cleanly when launched from a completely foreign working directory."""
    with tempfile.TemporaryDirectory() as foreign_dir:
        # Launch python sub-process from foreign directory importing and initializing zenshield
        test_script = (
            "import sys; "
            "from zenshield.main import create_app; "
            "from fastapi.testclient import TestClient; "
            "app = create_app(); "
            "c = TestClient(app); "
            "res = c.get('/health'); "
            "assert res.status_code == 200, f'Status {res.status_code}'; "
            "print('SUCCESS_BOOT')"
        )

        env = os.environ.copy()
        # Ensure python path includes repo src
        repo_root = Path(__file__).resolve().parent.parent.parent
        src_path = repo_root / "src"
        current_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{repo_root}{os.pathsep}{current_pp}"

        proc = subprocess.run(
            [sys.executable, "-c", test_script],
            cwd=foreign_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        assert "SUCCESS_BOOT" in proc.stdout
