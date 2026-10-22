import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.main import (
    app,
    Base,
    User,
    Grant,
    AuditEvent,
    get_db,
    password_hash,
    verify_audit_chain,
    audit_payload,
)



@pytest.fixture()
def env(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )
    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db

    import app.main as main

    monkeypatch.setattr(main, "STORAGE_DIR", tmp_path / "files")
    main.STORAGE_DIR.mkdir(exist_ok=True)

    with TestingSession() as db:
        owner = User(
            email="owner@example.com",
            display_name="Owner",
            password_hash=password_hash.hash("Owner-password-2026!"),
            role="owner",
        )
        viewer = User(
            email="viewer@example.com",
            display_name="Viewer",
            password_hash=password_hash.hash("Viewer-password-2026!"),
            role="viewer",
        )
        other = User(
            email="other@example.com",
            display_name="Other",
            password_hash=password_hash.hash("Other-password-2026!"),
            role="owner",
        )
        admin = User(
            email="admin@example.com",
            display_name="Admin",
            password_hash=password_hash.hash("Admin-password-2026!"),
            role="admin",
        )

        db.add_all([owner, viewer, other, admin])
        db.commit()

        ids = {
            user.email: user.id
            for user in [owner, viewer, other, admin]
        }

    clients = {name: TestClient(app) for name in ids}

    for name, client in clients.items():
        response = client.post(
            "/api/auth/login",
            json={
                "email": name,
                "password": (
                    name.split("@")[0].capitalize()
                    + "-password-2026!"
                ),
            },
        )
        assert response.status_code == 200, response.text

    yield {
        "clients": clients,
        "ids": ids,
        "session": TestingSession,
        "engine": engine,
    }

    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def upload(client, title="Confidential contract"):
    return client.post(
        "/api/documents",
        data={
            "title": title,
            "category": "Legal",
            "description": "private",
        },
        files={
            "file": (
                "contract.txt",
                b"only the intended user can read this",
                "text/plain",
            )
        },
    )


def test_unauthorized_user_cannot_list_or_download_private_document(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    assert viewer.get("/api/documents").status_code == 200
    assert viewer.get(
        f"/api/documents/{doc['id']}/download"
    ).status_code == 403


def test_grant_and_revoke_takes_effect_immediately(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    viewer_id = env["ids"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    grant = owner.put(
        f"/api/documents/{doc['id']}/grants",
        json={"user_id": viewer_id, "permission": "read"},
    )
    assert grant.status_code == 200, grant.text

    assert viewer.get(
        f"/api/documents/{doc['id']}/download"
    ).status_code == 200

    revoked = owner.delete(
        f"/api/documents/{doc['id']}/grants/{viewer_id}"
    )
    assert revoked.status_code == 200, revoked.text

    assert viewer.get(
        f"/api/documents/{doc['id']}/download"
    ).status_code == 403


def test_read_grant_cannot_edit_or_delete(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    viewer_id = env["ids"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    grant = owner.put(
        f"/api/documents/{doc['id']}/grants",
        json={"user_id": viewer_id, "permission": "read"},
    )
    assert grant.status_code == 200, grant.text

    edit = viewer.patch(
        f"/api/documents/{doc['id']}",
        json={"title": "Changed title", "category": "Legal"},
    )
    assert edit.status_code == 403

    delete = viewer.delete(f"/api/documents/{doc['id']}")
    assert delete.status_code == 403


def test_non_owner_cannot_grant_access(env):
    owner = env["clients"]["owner@example.com"]
    other = env["clients"]["other@example.com"]
    viewer_id = env["ids"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    grant = other.put(
        f"/api/documents/{doc['id']}/grants",
        json={"user_id": viewer_id, "permission": "read"},
    )
    assert grant.status_code == 403


def test_upload_rejects_bad_extension_and_mismatched_pdf(env):
    owner = env["clients"]["owner@example.com"]

    bad_extension = owner.post(
        "/api/documents",
        data={"title": "Executable", "category": "Test"},
        files={
            "file": (
                "malware.exe",
                b"not a real document",
                "application/octet-stream",
            )
        },
    )
    assert bad_extension.status_code == 415

    bad_pdf = owner.post(
        "/api/documents",
        data={"title": "Fake PDF", "category": "Test"},
        files={
            "file": (
                "fake.pdf",
                b"this is not a PDF",
                "application/pdf",
            )
        },
    )
    assert bad_pdf.status_code == 415


def test_audit_records_denied_attempt_and_chain_verifies(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    admin = env["clients"]["admin@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    denied = viewer.get(
        f"/api/documents/{doc['id']}/download"
    )
    assert denied.status_code == 403

    events = admin.get("/api/admin/audit?outcome=denied").json()
    assert any(
        event["action"] == "document.read"
        and event["document_id"] == doc["id"]
        for event in events
    )

    assert admin.get("/api/admin/audit/verify").json()["valid"] is True


def test_viewer_cannot_open_admin_audit(env):
    viewer = env["clients"]["viewer@example.com"]
    assert viewer.get("/api/admin/audit").status_code == 403


def test_logout_revokes_session(env):
    client = env["clients"]["viewer@example.com"]

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/me").status_code == 401


def test_inactive_user_cannot_use_existing_session(env):
    client = env["clients"]["viewer@example.com"]

    with env["session"]() as db:
        user = db.get(User, env["ids"]["viewer@example.com"])
        assert user is not None
        user.active = False
        db.commit()

    response = client.get("/api/me")
    assert response.status_code == 401


def test_viewer_cannot_upload(env):
    viewer = env["clients"]["viewer@example.com"]

    response = viewer.post(
        "/api/documents",
        data={"title": "nope", "category": "private"},
        files={
            "file": (
                "note.txt",
                b"not allowed",
                "text/plain",
            )
        },
    )
    assert response.status_code == 403


def test_audit_chain_detects_modified_event(env):
    owner = env["clients"]["owner@example.com"]
    response = upload(owner)
    assert response.status_code == 201, response.text

    with env["session"]() as db:
        event = db.scalar(
            select(AuditEvent).order_by(AuditEvent.id).limit(1)
        )
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
    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    response = client.get(
        f"/api/documents/{doc['id']}/download"
    )
    assert response.status_code == 401


def test_edit_grant_allows_update_but_not_delete(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    viewer_id = env["ids"]["viewer@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    grant = owner.put(
        f"/api/documents/{doc['id']}/grants",
        json={"user_id": viewer_id, "permission": "edit"},
    )
    assert grant.status_code == 200, grant.text

    edit = viewer.patch(
        f"/api/documents/{doc['id']}",
        json={"title": "Updated contract", "category": "Legal"},
    )
    assert edit.status_code == 200, edit.text

    delete = viewer.delete(f"/api/documents/{doc['id']}")
    assert delete.status_code == 403


def test_denied_delete_is_recorded_in_audit_trail(env):
    owner = env["clients"]["owner@example.com"]
    viewer = env["clients"]["viewer@example.com"]
    admin = env["clients"]["admin@example.com"]

    response = upload(owner)
    assert response.status_code == 201, response.text
    doc = response.json()

    denied = viewer.delete(f"/api/documents/{doc['id']}")
    assert denied.status_code == 403

    events = admin.get("/api/admin/audit?outcome=denied").json()
    assert any(
        event["action"] == "document.delete"
        and event["document_id"] == doc["id"]
        for event in events
    )

    assert admin.get("/api/admin/audit/verify").json()["valid"] is True


def test_production_rejects_sqlite_database():
    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "production",
            "DATABASE_URL": "sqlite:///./should_not_start.db",
            "AUDIT_HMAC_KEY": "test-audit-key-long-enough-for-production",
            "SESSION_SECRET": "test-session-secret-long-enough-for-production",
            "SESSION_COOKIE_SECURE": "true",
            "BOOTSTRAP_ADMIN_PASSWORD": "A-unique-production-password-2026!",
        }
    )

    result = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        env=env,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )

    assert result.returncode != 0
    assert "Production requires PostgreSQL" in (
        result.stdout + result.stderr
    )
def test_audit_payload_normalizes_utc_timestamps():
    from datetime import datetime, timezone

    timestamp = datetime(
        2026, 10, 21, 9, 27, 50, 887291
    )
    aware_timestamp = timestamp.replace(tzinfo=timezone.utc)

    common = {
        "actor_id": 1,
        "actor_email": "test@example.com",
        "action": "test",
        "document_id": None,
        "target_user_id": None,
        "outcome": "success",
        "detail": "",
        "previous_hash": "0" * 64,
    }

    naive_payload = audit_payload(at=timestamp, **common)
    aware_payload = audit_payload(at=aware_timestamp, **common)

    assert naive_payload == aware_payload
