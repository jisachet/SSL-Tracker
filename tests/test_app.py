import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models import Domain

# In-memory SQLite for testing with StaticPool so all connections share the same in-memory DB
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)

@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_index_empty_state(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "No domains tracked yet" in response.text

def test_add_domain_and_uniqueness(client, test_db):
    # Add domain
    res = client.post(
        "/domains/new",
        data={"hostname": "example.com", "port": 443, "label": "Test Bank", "notes": "Core API"},
        follow_redirects=True,
    )
    assert res.status_code == 200

    domain = test_db.query(Domain).filter(Domain.hostname == "example.com").first()
    assert domain is not None
    assert domain.port == 443
    assert domain.label == "Test Bank"

    # Attempt duplicate
    res_dup = client.post(
        "/domains/new",
        data={"hostname": "example.com", "port": 443},
        follow_redirects=True,
    )
    assert res_dup.status_code == 400
    assert "already being tracked" in res_dup.text

def test_bulk_add_domains(client, test_db):
    bulk_data = """
    bank1.example.com
    bank2.example.com:8443
    https://invalid-scheme.com
    bank1.example.com
    """
    res = client.post(
        "/domains/bulk",
        data={"domain_list": bulk_data, "bulk_label": "Fintech Cluster"},
    )
    assert res.status_code == 200
    assert "Batch Import Summary" in res.text
    assert "bank1.example.com" in res.text
    assert "bank2.example.com:8443" in res.text
    assert "https://invalid-scheme.com" in res.text

    domains = test_db.query(Domain).all()
    assert len(domains) == 2

def test_edit_and_delete_domain(client, test_db):
    d = Domain(hostname="editme.com", port=443, label="Original")
    test_db.add(d)
    test_db.commit()
    test_db.refresh(d)

    # Edit
    res_edit = client.post(
        f"/domains/{d.id}/edit",
        data={"hostname": "edited.com", "port": 8443, "label": "Updated", "notes": "New notes"},
        follow_redirects=True,
    )
    assert res_edit.status_code == 200

    test_db.refresh(d)
    assert d.hostname == "edited.com"
    assert d.port == 8443
    assert d.label == "Updated"

    # Delete
    res_del = client.post(f"/domains/{d.id}/delete", follow_redirects=True)
    assert res_del.status_code == 200
    assert test_db.query(Domain).filter(Domain.id == d.id).first() is None

def test_export_csv(client, test_db):
    d = Domain(hostname="csvtest.com", port=443, label="CSV Bank", status="OK", days_remaining=50)
    test_db.add(d)
    test_db.commit()

    res = client.get("/export/csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "csvtest.com" in res.text
    assert "CSV Bank" in res.text
    assert "Hostname,Port,Label,Status" in res.text
