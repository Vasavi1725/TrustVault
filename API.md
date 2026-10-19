# TrustVault API access matrix

All API endpoints except `GET /`, `GET /health`, and `POST /api/auth/login` require an active authenticated session cookie. The cookie is HttpOnly, SameSite=Strict, and Secure in production. Mutating requests with an Origin header must match the request host.

| Method | Endpoint | Who may call | Notes |
|---|---|---|---|
| GET | `/` | Public | UI shell only; no documents embedded |
| GET | `/health` | Public | Health check only |
| POST | `/api/auth/login` | Public | PBKDF2-HMAC-SHA256 password verification; session issued on success |
| POST | `/api/auth/logout` | Any authenticated user | Revokes server-side session |
| GET | `/api/me` | Any authenticated user | Current user's non-secret profile |
| GET | `/api/users` | Any authenticated user | Active users' names/emails for named sharing |
| POST | `/api/admin/users` | Admin | Creates admin/owner/viewer; password must be 12+ characters |
| POST | `/api/documents` | Owner, Admin | Upload validates extension, size, content signature/UTF-8 |
| GET | `/api/documents` | Any authenticated user | Results are restricted to readable documents; supports q, owner, category, date_from, date_to |
| GET | `/api/documents/{id}` | Owner, Admin, or explicit read/edit grantee | Denied access is audited |
| GET | `/api/documents/{id}/download` | Owner, Admin, or explicit read/edit grantee | Authorization and SHA-256 integrity check before serving |
| PATCH | `/api/documents/{id}` | Owner, Admin, or edit grantee | Updates title/category/description |
| DELETE | `/api/documents/{id}` | Owner, Admin, or edit grantee | Soft-deletes document and removes it from active routes |
| PUT | `/api/documents/{id}/grants` | Owner or Admin | Grants read/edit to a named active user |
| DELETE | `/api/documents/{id}/grants/{user_id}` | Owner or Admin | Revokes access; subsequent requests fail |
| GET | `/api/documents/{id}/grants` | Owner or Admin | Lists named grants |
| GET | `/api/admin/audit` | Admin | Audit events; optional outcome filter and limit |
| GET | `/api/admin/audit/verify` | Admin | Verifies HMAC chain and records verification attempt |
| GET | `/api/admin/summary` | Admin | Counts and audit-chain status |

## Error conventions

- `401`: missing/expired/revoked session.
- `403`: authenticated but not permitted; document authorization denials are audited when the document exists.
- `404`: document or grant does not exist or is soft-deleted.
- `409`: duplicate email.
- `413`: upload exceeds configured size.
- `415`: disallowed extension or content mismatch.
- `422`: invalid input.

## Important implementation note

The role model is intentionally simple. Admins can access all documents for administration; owners control grants for their own documents; viewers require a grant. If the product policy should forbid administrators from reading document contents, change the policy and tests explicitly rather than relying on UI behavior.
