import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add parent directory to sys.path to ensure main import works when running pytest
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app

client = TestClient(app)


def test_root_endpoint():
    """
    Test GET / endpoint returns 200 OK and expected JSON structure.
    """
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "RedFlag Backend API"
    assert data["status"] == "online"
    assert data["documentation"] == "/docs"


def test_health_endpoint():
    """
    Test GET /health endpoint returns 200 OK and healthy status.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
