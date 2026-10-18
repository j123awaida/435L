# Required API coverage — Joseph Awaida

A = Security Administrator, S = Security Analyst, E = Regular Employee/User, R = Auditor. Every route is prefixed by `/Joseph-Awaida`. Unlisted roles are rejected. `docs/API.md` and the OpenAPI exports describe fields and formats.

| Service | Method and route | Allowed roles | Key rule |
|---|---|---|---|
| 7 | POST /vulnerabilities | A | Existing asset; CVE format; CVSS 0–10; valid severity; owner alert queued |
| 7 | GET /vulnerabilities | A,S,R | Ordered results; pagination |
| 7 | GET /vulnerabilities/{id} | A,S,R | 404 for nonexistent id |
| 7 | PUT /vulnerabilities/{id} | A,S | One-step lifecycle; server resolution date |
| 7 | GET /vulnerabilities/search | A,S,R | CVE, severity, asset and status; AND filters |
| 7 | DELETE /vulnerabilities/{id} | A | Role check; missing record is 404 |
| 8 | POST /notifications | A | Existing recipient; valid type/severity; optional duplicate protection |
| 8 | GET /notifications/user/{user_id} | A,S,E,R | S/E only own recipient id; empty results allowed |
| 8 | GET /notifications/{id} | A,S,E,R | S/E only own alerts; missing record is 404 |
| 8 | PUT /notifications/{id}/read | A,S,E | S/E only own alerts; first read timestamp preserved |
| 8 | GET /notifications/search | A,S,R | S only own records; recipient/type/severity/status filters |
| 8 | DELETE /notifications/{id} | A | Role check; receipts prevent duplicate retry recreation |
| 9 | POST /playbooks | A | Required name/description/category/severity |
| 9 | GET /playbooks | A,S,R | Ordered list |
| 9 | GET /playbooks/{id} | A,S,R | Metadata, ordered actions and execution history |
| 9 | POST /playbooks/{id}/actions | A,S | Unique positive step; no insertion before a started action |
| 9 | PUT /actions/{id}/status | A,S | Qualified active assignee; ordered status progression; completion timestamp |
| 9 | DELETE /playbooks/{id} | A | Current actions cascade; history remains |

## Cross-cutting requirements

- Persistent relational schema, primary/foreign keys, database checks, and local reference users/assets: `app/schema.sql`.
- Login, hashed passwords, token sessions, active account verification, role checks and permission-denial audit: `app/auth.py`, `app/common.py`.
- Automatic successful-change logging: middleware in `app/common.py`; forwarding to the team's Service 5 is a documented integration boundary.
- Request validation/response models: `app/models.py`; unknown body fields are rejected.
- HTTP communication and retry behavior: `app/integration.py`, `scripts/notification_worker.py`.
- Tests: `tests/test_services.py`, `tests/test_integration.py`; actual JUnit and Newman results in `evidence/`.
- Actual database schema/records/before-after changes: `evidence/database-schema.json`, `database-records.json`, `database-transitions.json`.
- Editable and paginated contribution reports, diagrams, API reference and complete collection: `docs/`, `postman/`.
- Remaining genuine screenshots, team tasks and personal participation: `docs/SUBMISSION-CHECKLIST.md`.

No implementation, screenshot, or contribution from teammates has been invented. This matrix describes only Joseph's three services and their local supporting adapters.
