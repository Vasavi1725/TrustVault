# Five-Minute Demo Video Plan

Use real accounts created in the deployed application. Do not show production secrets or use the bootstrap password.

- **0:00–0:30 — Problem and roles:** Explain Owner, Viewer, Admin, and the default-deny policy.
- **0:30–1:15 — Upload and search:** Sign in as Owner A, upload a harmless PDF or TXT file, and search by title, category, and date.
- **1:15–2:00 — Unauthorized access:** Sign in as Viewer B in a separate browser session. Attempt to access Owner A’s document URL or download endpoint without permission. Show the denial and the corresponding Admin audit entry, if available.
- **2:00–2:45 — Grant and revoke:** Grant Viewer B read access. Demonstrate that download works while edit and delete remain forbidden. Revoke access and demonstrate that a subsequent download is denied.
- **2:45–3:30 — Audit evidence:** As Admin, filter denied events and show grant, revoke, and download events. Run the audit-chain verification feature if available in the deployed interface.
- **3:30–4:15 — Authorization and tests:** Show `pytest -q` and explain the cross-user access tests. Include `test_user_list_requires_owner_or_admin`, which checks that viewers cannot enumerate users while owners and admins can access the list for sharing. Clearly distinguish local test results from live deployment checks.
- **4:15–5:00 — Threats and limitations:** Explain the HMAC audit chain and database protections accurately. Discuss the external immutable-archive limitation and omitted features such as rate limiting, malware scanning, MFA, and RAG.

## Demo accuracy checklist

- Show only behavior that you have actually verified.
- Do not claim a live authorization check passed until you have observed its result.
- Do not expose passwords, session cookies, secret keys, or private document contents.
- Use harmless sample documents and purpose-created demo accounts.
- Report local automated test results separately from manual live checks.
