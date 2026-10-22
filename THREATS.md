# THREATS.md — TrustVault security analysis

This document describes the threat model for the current implementation. Update it with the actual result of every deployed test. A passing local test is not proof that the live service is safe.

## Assets and trust boundaries

- Confidential uploaded document bytes.
- Document metadata and ownership/grant records.
- User credentials and live sessions.
- Audit events used to investigate access.
- HMAC key, session signing secret, database credentials, and deployment secrets.

The browser is untrusted. All client-supplied IDs, filenames, MIME types, roles, and permission choices are untrusted. The API and database enforce access. In production, uploaded objects are stored in a private Supabase bucket and accessed through the authorized API; local development can use private local storage. Files use server-generated storage names. Production storage must remain private and must not expose public object URLs.
## Permission model

- Admin: operational access to all active documents and audit views; can create users and manage grants.
- Owner: full access to their documents; only the owner/admin can grant or revoke access.
- Viewer: read/download only after an explicit named-user grant.
- `read` does not permit edits/deletes. `edit` permits metadata edit and delete.
- No folder inheritance, public links, or implicit access from being in the same category.
- Access revocation removes the grant row. Each request checks the current grant in the database, so subsequent requests fail. It cannot erase bytes a user already downloaded or screenshots/copies they made.

## Threat register

| ID | Threat / attack | Mitigation in code | Test / evidence | Remaining risk |
|---|---|---|---|---|
| T01 | Guess document IDs and fetch another user's metadata | Every detail/download/update/delete path loads the document and checks the current user/role/grant | `test_unauthorized_user_cannot_list_or_download_private_document` | Test the deployed system too |
| T02 | Call download endpoint directly while UI hides the button | Authorization runs in backend route before file is returned | Same test; direct URL request | Any future endpoint must reuse the policy check |
| T03 | Read grant used to edit or delete | Separate `can_read` and `can_edit` checks | `test_read_grant_does_not_allow_edit_or_delete` | Review every new mutation route |
| T04 | Non-owner grants access to someone else | Grant/revoke require document owner or admin | `test_non_owner_cannot_grant_access` | Admin intentionally has broad powers |
| T05 | Reuse old access after revocation | Grant is deleted from DB; each subsequent request checks DB again; no long-lived signed download URLs | `test_grant_and_revoke_takes_effect_immediately` | Cannot retract already downloaded copies or in-flight responses |
| T06 | Cross-site request forgery | HttpOnly, SameSite=Strict cookie; mutating requests with Origin must match Host | Manual cross-origin POST/PUT/PATCH/DELETE test still required | Same-origin XSS could still perform actions; add CSP and XSS review |
| T07 | Session replay after logout | Opaque random session token; only its SHA-256 hash is stored; logout revokes DB session | `test_logout_revokes_session` | Session TTL is fixed/configured; rotate/revoke sessions after credential reset in future |
| T08 | Password database leak | PBKDF2-HMAC-SHA256 with unique random salt and 600,000 iterations | Code review of `PasswordHash` | Argon2id is preferable where available; consider migration and tune cost on production hardware |
| T09 | Upload extension spoofing | Allow-list extensions, size limit, signature checks for PDF/images, UTF-8 checks for text/CSV; random server filename | `test_upload_rejects_bad_extension_and_mismatched_pdf` | No malware scanner; signature checks do not fully validate file structure |
| T10 | Path traversal via filename | User filename is reduced to basename; stored path uses server-generated UUID and fixed extension | Review upload/download code | Add dedicated traversal tests and malware scanning before production |
| T11 | Stored file modified after upload | SHA-256 is recorded and checked again before download | Manual test: modify stored bytes, expect 500 and audit event | File hash is not a digital signature; storage host compromise remains in scope |
| T12 | Audit row changed or reordered | HMAC-SHA256 chain; HMAC key is separate from DB; SQLite/PostgreSQL triggers reject ordinary UPDATE/DELETE | `test_audit_records_denied_attempt_and_chain_verifies`; add explicit tamper test | DB superuser can drop triggers; tail truncation cannot be proven without external checkpointing. Export signed checkpoints to independent WORM storage for production |
| T13 | Unauthorized attempt goes unrecorded | Known-document denied read/edit/grant/revoke attempts are audited with actor/outcome | `test_audit_records_denied_attempt_and_chain_verifies` | Unknown IDs and failures before document lookup may not produce a document-specific event |
| T14 | Audit details leak secrets | Passwords/tokens/file contents are not logged; upload logs hash/size; update logs field-level action only | Code review | Avoid adding PII or sensitive document text to `detail` |
| T15 | Viewer accesses admin audit endpoints | Role dependency restricts admin routes | `test_viewer_cannot_open_admin_audit` | Add tests for every future admin route |
| T16 | Brute-force login | PBKDF2 increases per-guess cost | No automated rate-limit test yet | **Accepted MVP gap:** no distributed rate limiter/account lockout; add reverse-proxy or Redis-backed rate limiting before production |
| T17 | Admin account takeover | Bootstrap password configurable; production startup rejects default password and weak/missing secrets; session cookie Secure required in production | Verify deployment environment and change bootstrap password | No MFA/password reset workflow yet; add MFA for production |
| T18 | Database injection | SQLAlchemy query expressions and bound parameters used for DB queries | Code review and API fuzz tests still required | Do not construct SQL from user strings; keep dependencies patched |
| T19 | Large upload exhausts memory/disk | Configured upload cap, reads at most cap + 1 bytes, deployment storage limit | Upload boundary tests still required | Concurrent upload rate limiting and disk quotas are not implemented |
| T20 | Race causes inconsistent audit chain | PostgreSQL advisory transaction lock serializes chain append | Needs concurrent PostgreSQL integration test | SQLite local mode is for development; validate concurrency on production PostgreSQL |
| T21 | App process crashes between file write and DB commit | File name is random and metadata records content hash | Manual failure-injection test not yet added | Orphan file cleanup job is not implemented |
| T22 | Soft-deleted file recovered from disk by host operator | API routes treat deleted record as not found; audit retained | Verify deleted IDs return 404 | File bytes remain in private storage; retention/purge policy is not implemented |
| T23 | XSS in document metadata | UI renders API values via `textContent`, not interpolated HTML | Code review | Add a strict Content-Security-Policy and test all future UI changes |
| T24 | Public URL or static mount exposes file bytes | Private upload directory is not mounted as static content; downloads go through authorized API | Verify storage paths cannot be fetched directly | Deployment must not add a public static mapping or public object ACL |
| T25 | Admin misuse | Admin actions are audited; admin role can be reviewed in activity view | Manual role audit | Separation of duties and approval workflow are not implemented |
| T26 | Malicious prompt injection in a future RAG feature | RAG is not in this MVP; if added, permission filter must run before retrieval and retrieved text remains untrusted data | No RAG code exists yet | Do not ship RAG until access-filtered retrieval and adversarial tests pass |

## Audit integrity limitations (be precise in the demo)

The HMAC chain detects changes to event content and most reordering/deletion when the key remains secret. Database triggers add protection against accidental or ordinary row mutation. A database superuser can alter the schema, and deletion of the final rows of a chain cannot be independently detected from that same database alone. A real enterprise deployment should stream events and signed sequence checkpoints to a separate security account / immutable log store, monitor delivery gaps, and alert on verification failure.

## Required manual tests against the deployed URL

1. Sign in as Owner A, upload a unique private file, and record its ID.
2. Sign in as Viewer B in a different browser. Try list search, detail URL, download URL, PATCH, DELETE, grant, and revoke. Confirm no document bytes/metadata are returned and relevant denials appear in the Admin audit view.
3. Grant B `read`, confirm download works but PATCH/DELETE fail.
4. Revoke B's grant, then repeat detail and download immediately; both must fail.
5. Upload a renamed executable, fake PDF, empty file, and over-limit file; verify rejection.
6. Tamper with a stored file in a local test environment; verify download fails integrity check.
7. Verify audit chain, change an audit event in a disposable test database, and confirm verification fails.
8. Try a cross-origin mutating request and confirm it is rejected.
9. Open the deployment in a private window and confirm private storage is not directly accessible.

## Accepted MVP omissions

No MFA, external identity provider, password reset, distributed rate limiting, malware scanning, external immutable audit archive, folder inheritance, public sharing, versioning, legal hold, or RAG. These are not silently claimed as complete. For the challenge, document them honestly and prioritize closing authorization gaps over adding features.
