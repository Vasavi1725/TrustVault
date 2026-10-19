# PROMPTS.md — AI-assisted development log

**Important:** This is a working log starter based on the actual implementation/review work on 2026-10-19. Before submitting, update each entry with the real Git commit URL after committing the relevant change. Do not invent commit hashes or claim a test was run if it was not. Keep adding entries on the day you use AI.

## Reusable project context used

> Build TrustVault according to the supplied challenge specification. Treat this as a security application, not a CRUD demo. The backend is authoritative for every document read, download, update, delete, grant, and revoke. Default deny. No public file URLs. Permission revocation must apply to the next request. Audit successful and denied actions. Tests must fail if an authorization check is removed. Do not claim security guarantees that are not implemented or tested. Explain every accepted risk in THREATS.md.

## Entry 1 — 2026-10-19 — Initial architecture and implementation

- **Prompt / request:** Implement a workable TrustVault secure document-sharing application matching the challenge: three roles, per-document read/edit grants, upload validation, search, audit, automated tests, docs, and deployment.
- **What the AI produced:** A FastAPI application with server-side opaque sessions, SQLAlchemy models, private file storage, permission checks on document endpoints, and an HMAC-chained audit log.
- **What needed scrutiny:** A generated application can appear complete while an endpoint misses an authorization check. The first design review therefore treated every document route independently and added tests for direct detail/download, update/delete, grants, and revocation.
- **What I did:** Added `tests/test_security.py` and documented the policy in `README.md` / `API.md`.
- **Commit:** TODO — add the real GitHub commit URL after committing this implementation.

## Entry 2 — 2026-10-19 — Password-hashing dependency review

- **Prompt / request:** Make the project runnable and use a suitable password-hashing scheme.
- **What the AI initially produced:** A `pwdlib` / Argon2 integration.
- **What was wrong:** The current build environment could not install new packages because package-index networking was unavailable, so the implementation could not be imported and tested there. This did not mean Argon2 was unsafe; it was a dependency/verification problem.
- **What I did instead:** Replaced that dependency with Python's standard-library PBKDF2-HMAC-SHA256, a unique random salt, and 600,000 iterations; updated requirements and docs. Argon2id remains a reasonable future upgrade after deployment benchmarking.
- **Verification:** The security test suite subsequently ran successfully in the available environment.
- **Commit:** TODO — add the real GitHub commit URL.

## Entry 3 — 2026-10-19 — Authorization: viewer upload

- **Prompt / request:** Review role boundaries and make sure the backend enforces them rather than relying on the UI.
- **What the AI review found:** The first upload route allowed any authenticated user to upload even though the intended policy was that Viewer is read-only.
- **What I did:** Restricted upload to `owner` and `admin` in the backend and hid the upload form for viewers as a usability measure. The backend dependency is the actual security control; the UI is not.
- **Verification:** Add/retain a regression test asserting Viewer upload is rejected before submission.
- **Commit:** TODO — add the real GitHub commit URL.

## Entry 4 — 2026-10-19 — Audit integrity and atomicity

- **Prompt / request:** Review whether the audit trail could be changed quietly and whether the document mutation and its audit record are committed together.
- **What the AI initially produced:** An HMAC chain that could detect event-content edits but did not yet prevent ordinary database updates/deletes, and some mutation handlers committed the document change before writing the audit event.
- **What was wrong:** Separate commits create a crash window where a document operation may succeed without its audit event. A chain stored only in one database also cannot independently prove that the tail was truncated.
- **What I did:** Added SQLite/PostgreSQL triggers against audit-row update/delete, a PostgreSQL advisory lock for serializing chain appends, and changed key mutation handlers so the business change and audit insert are committed by the same audit commit. Documented the remaining superuser/tail-truncation limitation and the need for external immutable checkpoints.
- **Verification:** Run the test suite and add an explicit tamper-detection test before submission.
- **Commit:** TODO — add the real GitHub commit URL.

## Entry 5 — 2026-10-19 — Upload validation and file integrity

- **Prompt / request:** Check file upload security, filename handling, and download integrity.
- **What the AI review found:** Client-provided filenames and MIME types cannot be trusted; a file extension alone does not prove file type. An early implementation also mutated a shared allowed-type set while choosing a response content type.
- **What I did:** Use a server-generated UUID for storage names, allow-list extensions, enforce size limits, check PDF/image signatures and UTF-8 for text/CSV, and store SHA-256 for verification before download. The content-type set mutation was removed.
- **Remaining issue:** Signature checks are not full malware scanning or complete format validation. This is explicitly accepted in `THREATS.md` rather than presented as solved.
- **Commit:** TODO — add the real GitHub commit URL.

## Future entries — fill in during real work

For every later AI-assisted change, record the date, the actual prompt (or a fair summary), the generated output, the specific error or assumption you checked, your correction, test evidence, and a real commit URL. At least two entries must concern authorization/access control/audit, as required by the challenge. Do not leave this file until the last evening.
