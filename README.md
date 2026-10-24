# TrustVault — secure document sharing with a real audit trail

A small, security-first document platform built with **Python 3.12, FastAPI, SQLAlchemy, PostgreSQL (production) / SQLite (local), PBKDF2-HMAC-SHA256 password hashing, opaque server-side sessions, and an HMAC-chained audit log**. The web UI is intentionally lightweight and served by FastAPI.

> **Challenge note:** This is a security-focused prototype, not independently security-certified. Read `THREATS.md`, run the tests, and fix/record any issue you find before submission. Do not submit generated code without understanding and verifying it.

## Role model

- **Administrator:** view all active documents, inspect activity and permission changes, verify the audit chain, and create users. The admin can manage any document's grants.
- **Document Owner:** upload documents; read, download, update, and soft-delete their own documents; grant/revoke `read` or `edit` access to named users.
- **Viewer:** read/download only documents explicitly shared with them. A read grant does not allow editing or deleting. Viewers cannot upload or share.
- **Edit grant:** permits reading, downloading, and editing metadata on the shared document. It does not permit deletion, transfer ownership, or further sharing.
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

TrustVault is deployed on Render and uses PostgreSQL for production data and Supabase private object storage for uploaded document bytes.

1. Deploy the repository as a Docker web service using `Dockerfile` / `render.yaml`, and provision a managed PostgreSQL database.
2. Configure these environment variables in the Render dashboard:
   - `DATABASE_URL` — the managed PostgreSQL connection URL.
   - `AUDIT_HMAC_KEY` — a unique, randomly generated secret used to authenticate audit events.
   - `SESSION_SECRET` — a separate unique, randomly generated session secret.
   - `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` — the initial administrator account settings.
   - `SESSION_COOKIE_SECURE=true` — require secure cookies over HTTPS.
   - `STORAGE_BACKEND=supabase`
   - `SUPABASE_URL` — your Supabase project URL.
   - `SUPABASE_SERVICE_ROLE_KEY` — the service-role secret; keep it only in server-side environment variables and never commit or expose it.
   - `SUPABASE_BUCKET=trustvault-documents` — the private bucket used for document storage.
3. In Supabase, create the `trustvault-documents` bucket and keep it private. Configure upload limits and allowed file types to match the application.
4. Confirm the Render service uses HTTPS and `/health` returns `{"status":"ok"}`.
5. Sign in as the administrator, use strong unique passwords, create owner/viewer accounts, and upload a harmless test document.
6. Verify upload and download, grant/revoke permissions, denied access, content-integrity checks, and the audit-chain verification against the live URL.
7. Test with a separate Viewer session and confirm that revoking a grant blocks access on the server, including direct download requests.

Do not commit `.env` files, database passwords, Supabase service-role keys, session secrets, or audit keys. Use separate random values for `SESSION_SECRET` and `AUDIT_HMAC_KEY`.

Supabase object storage is used for uploaded file bytes so they do not depend on an ephemeral Render filesystem. Database backups, storage retention, migrations, and production recovery should be planned separately. The application currently creates tables on startup; use controlled database migrations for a mature production deployment.

Live application: https://trustvault-904r.onrender.com

## API documentation

The OpenAPI schema is generated at `/openapi.json`; Swagger UI is at `/docs`. Endpoint access rules are summarized in `API.md`.

## Audit design and limits

Each event includes actor, action, document/target references, outcome, timestamp, previous hash, and an HMAC-SHA256 hash. The HMAC key must be kept outside the database. SQLite/PostgreSQL triggers reject ordinary UPDATE/DELETE operations on audit rows. `/api/admin/audit/verify` verifies the chain. Denied attempts are logged for known document IDs.

This detects content edits, interior deletions/reordering, and tampering without the HMAC key. A database superuser can drop triggers, and deleting the tail of a chain cannot be proven from the remaining database alone. For stronger production evidence, export signed checkpoints/events to a separately administered immutable/WORM log service or object-lock storage. Do not claim this prototype has tamper-proof external archival.

## Deliberately not included in the seven-day MVP

- Public/external sharing links, folder inheritance, groups, document versioning, malware scanning, SSO/MFA, email notifications, and AI/RAG.
- RAG is deliberately deferred until authorization tests pass. If added, filter by current user permissions **before retrieval**, re-check grants on every query, and treat document text as untrusted prompt-injection content.
- A full enterprise retention/legal hold workflow and external immutable audit sink remain future work and are disclosed in `THREATS.md`.

## Project status and known limitations

- **Source code:** Public repository with implementation history available in Git.
- **Deployment:** Live application: https://trustvault-904r.onrender.com
- **Security documentation:** See `THREATS.md` for threat scenarios, verification status, and accepted risks.
- **AI-use record:** See `PROMPTS.md` for dated entries describing AI assistance and implementation work.
- **Automated tests:** The latest recorded local run passed 20 tests, with 3 warnings. Re-run the tests before relying on this result.
- **Authorization:** User-directory access is restricted to owners and administrators. Document deletion is restricted to the document owner or an administrator.
- **Known limitations:** External immutable audit archival and enterprise retention/legal hold remain future work. See `THREATS.md`. This prototype is not independently security-certified.

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
