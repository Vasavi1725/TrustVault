
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app, Base, User, Grant, AuditEvent, get_db, password_hash, verify_audit_chain


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db

    # Ensure test file storage is isolated from developer files.
    import app.main as main
    monkeypatch.setattr(main, "STORAGE_DIR", tmp_path / "files")
    main.STORAGE_DIR.mkdir(exist_ok=True)

    with TestingSession() as db:
        owner = User(email="owner@example.com", display_name="Owner", password_hash=password_hash.hash("Owner-password-2026!"), role="owner")
        viewer = User(email="viewer@example.com", display_name="Viewer", password_hash=password_hash.hash("Viewer-password-2026!"), role="viewer")
        other = User(email="other@example.com", display_name="Other", password_hash=password_hash.hash("Other-password-2026!"), role="owner")
        admin = User(email="admin@example.com", display_name="Admin", password_hash=password_hash.hash("Admin-password-2026!"), role="admin")
        db.add_all([owner, viewer, other, admin])
        db.commit()
        ids = {u.email: u.id for u in [owner, viewer, other, admin]}

    clients = {name: TestClient(app) for name in ids}
    for name, client in clients.items():
        r = client.post("/api/auth/login", json={"email": name, "password": name.split('@')[0].capitalize()+"-password-2026!"})
        assert r.status_code == 200, r.text

    yield {"clients": clients, "ids": ids, "session": TestingSession, "engine": engine}

    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def upload(client, title="Confidential contract"):
    return client.post(
        "/api/documents",
        data={"title": title, "category": "Legal", "description": "private"},
        files={"file": ("contract.txt", b"only the intended user can read this", "text/plain")},
    )


def test_unauthorized_user_cannot_list_or_download_private_document(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    r = upload(owner)
    assert r.status_code == 201, r.text
    doc_id = r.json()["id"]
    assert viewer.get("/api/documents").json() == []
    assert viewer.get(f"/api/documents/{doc_id}").status_code == 403
    assert viewer.get(f"/api/documents/{doc_id}/download").status_code == 403


def test_grant_and_revoke_takes_effect_immediately(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    doc = upload(owner).json()
    grant = owner.put(f"/api/documents/{doc['id']}/grants", json={"user_id": env["ids"]["viewer@example.com"], "permission": "read"})
    assert grant.status_code == 200, grant.text
    assert viewer.get(f"/api/documents/{doc['id']}/download").status_code == 200
    revoked = owner.delete(f"/api/documents/{doc['id']}/grants/{env['ids']['viewer@example.com']}")
    assert revoked.status_code == 200, revoked.text
    assert viewer.get(f"/api/documents/{doc['id']}/download").status_code == 403


def test_read_grant_does_not_allow_edit_or_delete(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    doc = upload(owner).json()
    owner.put(f"/api/documents/{doc['id']}/grants", json={"user_id": env["ids"]["viewer@example.com"], "permission": "read"})
    assert viewer.patch(f"/api/documents/{doc['id']}", json={"title": "Changed", "category": "Legal", "description": ""}).status_code == 403
    assert viewer.delete(f"/api/documents/{doc['id']}").status_code == 403


def test_non_owner_cannot_grant_access(env):
    owner = env["clients"]["owner@example.com"]
    other = env["clients"]["other@example.com"]
    doc = upload(owner).json()
    response = other.put(f"/api/documents/{doc['id']}/grants", json={"user_id": env["ids"]["viewer@example.com"], "permission": "read"})
    assert response.status_code == 403


def test_upload_rejects_bad_extension_and_mismatched_pdf(env):
    owner = env["clients"]["owner@example.com"]
    bad_ext = owner.post("/api/documents", data={"title": "bad", "category": "x"}, files={"file": ("malware.exe", b"bad", "application/octet-stream")})
    assert bad_ext.status_code == 415
    bad_pdf = owner.post("/api/documents", data={"title": "bad", "category": "x"}, files={"file": ("fake.pdf", b"not a pdf", "application/pdf")})
    assert bad_pdf.status_code == 415


def test_audit_records_denied_attempt_and_chain_verifies(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    doc = upload(owner).json()
    assert viewer.get(f"/api/documents/{doc['id']}/download").status_code == 403
    admin = env["clients"]["admin@example.com"]
    events = admin.get("/api/admin/audit?outcome=denied").json()
    assert any(e["action"] == "document.read" and e["document_id"] == doc["id"] for e in events)
    assert admin.get("/api/admin/audit/verify").json()["valid"] is True


def test_viewer_cannot_open_admin_audit(env):
    assert env["clients"]["viewer@example.com"].get("/api/admin/audit").status_code == 403


def test_logout_revokes_session(env):
    client = env["clients"]["viewer@example.com"]
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/me").status_code == 401


def test_viewer_cannot_upload(env):
    viewer = env["clients"]["viewer@example.com"]
    response = viewer.post("/api/documents", data={"title": "nope", "category": "private"},
                           files={"file": ("note.txt", b"not allowed", "text/plain")})
    assert response.status_code == 403


def test_audit_chain_detects_modified_event(env):
    owner = env["clients"]["owner@example.com"]
    assert upload(owner).status_code == 201
    with env["session"]() as db:
        event = db.scalar(select(AuditEvent).order_by(AuditEvent.id).limit(1))
        assert event is not None
        event.detail = "tampered after the fact"
        db.commit()
        assert verify_audit_chain(db) is False


def test_unauthenticated_requests_are_rejected(env):
    client = TestClient(app)

    assert client.get("/api/me").status_code == 401
    assert client.get("/api/documents").status_code == 401
    assert client.get("/api/admin/audit").status_code == 401

    owner = env["clients"]["owner@example.com"]
    doc = upload(owner).json()

    response = client.get(f"/api/documents/{doc['id']}/download")
    assert response.status_code == 401


def test_edit_grant_allows_update_but_not_delete(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    viewer_id = env["ids"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    document_id = response.json()["id"]

    grant = owner.put(
        f"/api/documents/{document_id}/grants",
        json={"user_id": viewer_id, "permission": "edit"},
    )
    assert grant.status_code == 200, grant.text

    update = viewer.patch(
        f"/api/documents/{document_id}",
        json={
            "title": "Updated contract",
            "category": "Legal",
            "description": "Updated by an editor",
        },
    )
    assert update.status_code == 200, update.text

    # Editors may update metadata but cannot delete another user's document.
    delete = viewer.delete(f"/api/documents/{document_id}")
    assert delete.status_code == 403
