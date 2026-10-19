# TrustVault — secure document sharing with a real audit trail

A small, security-first document platform built with **Python 3.12, FastAPI, SQLAlchemy, PostgreSQL (production) / SQLite (local), PBKDF2-HMAC-SHA256 password hashing, opaque server-side sessions, and an HMAC-chained audit log**. The web UI is intentionally lightweight and served by FastAPI.

> **Challenge note:** This is a working starter implementation, not a claim of independent security certification. Read `THREATS.md`, run the tests, and fix/record any issue you find before submission. Do not submit generated code without understanding and verifying it.

## Role model

- **Administrator:** view all active documents, inspect activity and permission changes, verify the audit chain, and create users. The admin can manage any document's grants.
- **Document Owner:** upload documents; read, download, update, and soft-delete their own documents; grant/revoke `read` or `edit` access to named users.
- **Viewer:** read/download only documents explicitly shared with them. A read grant does not allow editing or deleting. Viewers cannot upload or share.
- **Edit grant:** permits reading, downloading, editing metadata, and deleting the shared document. It does not transfer ownership or permit further sharing.
- **Default:** no grant means no access. There is no folder inheritance or public sharing.

The backend is authoritative. Hiding a button in the UI is not an authorization check. Every document endpoint checks access on the server.

## Quick start (Windows PowerShell)

Install Python 3.12+, then from the project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set unique values for `AUDIT_HMAC_KEY` and `SESSION_SECRET` (add `SESSION_SECRET=...` if missing). Keep `.env` private. In local development, the example settings use SQLite and `SESSION_COOKIE_SECURE=false`; production must use HTTPS and `SESSION_COOKIE_SECURE=true`.

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. API docs: http://127.0.0.1:8000/docs. Health check: http://127.0.0.1:8000/health.

### Initial admin

On first startup, TrustVault creates the account configured by `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`. Defaults in `.env.example` are **development-only**. Change the password immediately and do not use those defaults in a public deployment. Create owner/viewer accounts through the Admin panel or `POST /api/admin/users`.

Example development accounts can be created from the admin panel. For a challenge deployment, create three separate accounts, set unique strong passwords, and put only the intended demo credentials in the README after you have changed the initial admin password. Never commit production secrets.

## Run automated tests

```powershell
pytest -q
```

The tests cover private document listing, direct detail/download access, grant/revoke, read-vs-edit, unauthorized grant changes, invalid upload content, denied-event auditing, audit verification, admin endpoint access, and logout/session revocation. Add a test for every entry in `THREATS.md` as you extend the application.

## Database

SQLite is used by default for local development. PostgreSQL is recommended for deployment. Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL, for example:

```text
postgresql+psycopg://trustvault_user:URL_ENCODED_PASSWORD@HOST:5432/trustvault
```

The application creates its tables on startup. For a team/production deployment, replace `create_all()` with Alembic migrations, run migrations as a controlled release step, and use a database user with least privilege.

## Deployment with Docker / Render

1. Create a managed PostgreSQL database.
2. Create a persistent disk for private uploads (or replace it with private object storage).
3. Deploy this repository as a Docker web service using `Dockerfile` / `render.yaml`.
4. Set `DATABASE_URL`, `AUDIT_HMAC_KEY`, `SESSION_SECRET`, `BOOTSTRAP_ADMIN_PASSWORD`, `SESSION_COOKIE_SECURE=true`, and `STORAGE_DIR=/var/data/private_uploads` in the hosting dashboard. Use unique random secrets. Do not put them in Git.
5. Confirm the service is served over HTTPS and `/health` returns `{"status":"ok"}`.
6. Sign in, change the bootstrap admin password, create owner/viewer accounts, upload test documents, and verify all security cases against the **live** URL.
7. Test from a private/incognito window and a second browser/device. Keep the repository private until the placement cell resolves the conflict between the email and the challenge's public-repository instruction.

The Render starter configuration assumes a paid web service/disk and a separately provisioned PostgreSQL database; plans/pricing can change. Local disk is not appropriate for ephemeral production containers. Do not deploy until the persistent storage and secrets are configured.

## API documentation

The OpenAPI schema is generated at `/openapi.json`; Swagger UI is at `/docs`. Endpoint access rules are summarized in `API.md`.

## Audit design and limits

Each event includes actor, action, document/target references, outcome, timestamp, previous hash, and an HMAC-SHA256 hash. The HMAC key must be kept outside the database. SQLite/PostgreSQL triggers reject ordinary UPDATE/DELETE operations on audit rows. `/api/admin/audit/verify` verifies the chain. Denied attempts are logged for known document IDs.

This detects content edits, interior deletions/reordering, and tampering without the HMAC key. A database superuser can drop triggers, and deleting the tail of a chain cannot be proven from the remaining database alone. For stronger production evidence, export signed checkpoints/events to a separately administered immutable/WORM log service or object-lock storage. Do not claim this prototype has tamper-proof external archival.

## Deliberately not included in the seven-day MVP

- Public/external sharing links, folder inheritance, groups, document versioning, malware scanning, SSO/MFA, email notifications, and AI/RAG.
- RAG is deliberately deferred until authorization tests pass. If added, filter by current user permissions **before retrieval**, re-check grants on every query, and treat document text as untrusted prompt-injection content.
- A full enterprise retention/legal hold workflow and external immutable audit sink remain future work and are disclosed in `THREATS.md`.

## Submission checklist

- [ ] Public Git repository when permitted by the challenge rules; commits across the week.
- [ ] Live URL, seed data, and three role credentials.
- [ ] `THREATS.md` updated with actual tests/results and accepted risks.
- [ ] `PROMPTS.md` with at least five real dated entries and actual commit links; at least two about authorization/audit.
- [ ] Tests pass from a clean clone.
- [ ] Database schema/setup and deployment instructions verified.
- [ ] Five-minute demo video recorded.
- [ ] Short write-up completed honestly, including unfinished items.

## Seed challenge demo data

After the app has started once and the bootstrap admin exists, create owner/viewer accounts and a harmless sample document with a read-only viewer grant. Set these variables in your shell or hosting job; never save the passwords in Git:

```powershell
$env:DEMO_OWNER_EMAIL = "owner-demo@example.com"
$env:DEMO_OWNER_PASSWORD = "Use-a-unique-owner-password!"
$env:DEMO_VIEWER_EMAIL = "viewer-demo@example.com"
$env:DEMO_VIEWER_PASSWORD = "Use-a-unique-viewer-password!"
python scripts/seed_demo.py
```

The script is idempotent for existing accounts/document: it does not reset existing passwords. Save the actual credentials in the deployment's secret manager. The challenge requires demo credentials in the README; publish only purpose-created demo accounts with no real data and confirm with the placement cell how they want credentials shared.
