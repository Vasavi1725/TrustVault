# TrustVault — submission write-up (complete after deployment)

## What I built

[Describe the working features and link to the live deployment.] Do not list a feature as complete unless you tested it.

## Permission model in my own words

- Admin: [confirm exact powers].
- Owner: [confirm exact powers].
- Viewer: [confirm exact powers].
- Read vs edit: [explain].
- Revocation: every request re-queries the current grant, so future requests fail after revocation. Already downloaded copies cannot be recalled.

## Security decisions

[Explain server-side checks, private storage, upload validation, session handling, audit chain, and the test that would fail if a check were removed.]

## AI use and errors caught

[Summarize actual PROMPTS.md entries and link to commits. Be specific about what was wrong and how you verified the correction.]

## Deliberately not built

[State real omissions: external immutable audit archive, MFA, distributed rate limiting, malware scanning, versioning, RAG, etc.]

## Test and deployment evidence

- Local test command and result: [paste actual output].
- Live URL and date tested: [fill in].
- Three demo accounts: [fill in only after setting unique passwords; never publish real production secrets in source code].
- Demo video: [link].

## Known gaps

[Be honest. Do not claim that a local test proves the deployed configuration is secure.]
