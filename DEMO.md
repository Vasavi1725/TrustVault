# Five-minute demo video plan

Use real accounts created in the deployed application. Do not show production secrets or use the bootstrap password.

- **0:00–0:30 — Problem and roles:** explain Owner, Viewer, Admin and the default-deny policy.
- **0:30–1:15 — Upload/search:** sign in as Owner A, upload a harmless PDF/TXT, search by title/category/date.
- **1:15–2:00 — Unauthorized attack:** sign in as Viewer B in a separate browser and try the direct document URL/download. Show the denial and the Admin audit entry.
- **2:00–2:45 — Grant and revoke:** grant Viewer B read access; show download works but edit/delete fail; revoke access and show the next download fails.
- **2:45–3:30 — Audit evidence:** as Admin, filter denied events, show grant/revoke/download events, and run audit-chain verification.
- **3:30–4:15 — Tests:** show `pytest -q` and explain the cross-user access test. Mention tests run locally and separately report live deployment tests.
- **4:15–5:00 — Threats and honest gaps:** explain HMAC chain + DB triggers, external immutable archive limitation, and omitted features (rate limiting, malware scanning, MFA, RAG).
