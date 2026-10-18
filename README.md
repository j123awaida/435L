# Security Incident Detection and Response — Joseph Awaida

Sprint I contribution: Service 7 (Vulnerabilities), Service 8 (Notifications), Service 9 (Playbooks and response actions). Python, FastAPI, SQLite. Backend only.

## Run locally

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m scripts.seed
.venv/bin/python -m scripts.run
```

The seed command creates four development users (`admin`, `analyst`, `employee`, `auditor`) with randomly generated passwords in `data/demo-credentials.json`, and two reference assets. It never overwrites existing users. Do not commit passwords, tokens, or the local database.

| Process | Port | Interactive documentation |
|---|---|---|
| Temporary identity adapter | 8000 | http://127.0.0.1:8000/docs |
| Vulnerabilities | 8007 | http://127.0.0.1:8007/docs |
| Notifications | 8008 | http://127.0.0.1:8008/docs |
| Playbooks/actions | 8009 | http://127.0.0.1:8009/docs |

Every API route starts with `/Joseph-Awaida`. Each service exposes `/Joseph-Awaida/health` and standard FastAPI `/docs` and `/openapi.json` documentation. Login at `POST http://127.0.0.1:8000/Joseph-Awaida/auth/login`, with JSON `{"username":"admin","password":"<local password>"}`. Supply the returned token as `Authorization: Bearer <access_token>`. Sessions last one hour; inactive/suspended users are rejected at login and on each request.

## Verify and capture evidence

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m scripts.diagrams
.venv/bin/python -m scripts.generate_artifacts
.venv/bin/python -m scripts.capture_evidence
```

Verified locally: 9 automated tests passed; 57 HTTP scenarios passed; the actual Postman collection passed all 57 requests/assertions in Newman. See `evidence/newman-output.txt`.

Start the servers before capturing evidence. The capture script executes real HTTP calls against the local processes and saves sanitized responses, a database snapshot, and the live OpenAPI specifications in `evidence/`. It deliberately retains demo records for inspection. Re-running it creates additional records. Automated HTTP evidence does not replace the required Postman screenshots.

Import `postman/Services-7-8-9.postman_collection.json` and its environment into Postman. Set passwords from the local credentials file, then run the login requests to populate token variables. Run folders in order. Capture real Postman requests/responses with captions identifying **Joseph Awaida**, operation, and purpose. Never include bearer tokens or passwords in public screenshots.

## Integration with teammates

The identity adapter, minimal users/assets reference tables, and local audit table are integration scaffolding for Services 1, 2, and 5; they are not complete implementations of teammates' services. All four processes currently use the same SQLite file (configurable through `DATABASE_PATH`), so ownership and foreign keys are enforced locally. They expose independent HTTP APIs. Replace the scaffolding with the team's identity verification, asset lookup, and audit API adapters when those contracts are supplied. Audit permission denials currently persist locally; forwarding to Service 5 remains a team integration task. Upstream services can create alerts through the administrator-authenticated Service 8 HTTP endpoint. No automatic incident/threat event producer is included in this contribution.

## Rules and design

- Roles: `admin` = Security Administrator, `analyst` = Security Analyst, `employee` = Regular Employee/User, `auditor` = Auditor.
- Vulnerabilities advance `Open → Under Investigation → In Progress → Resolved → Closed`; resolution timestamp is generated on resolution and preserved on closure. CVSS is 0–10; severity is a separate validated enum, as specified.
- Analyst/employee notification reads are restricted to their own records. Analysts search only their own notifications. Employees cannot search. Auditors can read/search but cannot mark read.
- Playbook actions have unique positive step numbers, execute in ascending order, and progress `Pending → In Progress → Completed`. An active administrator or analyst must be assigned before execution. Immutable action history survives playbook deletion.
- Parameterized SQL prevents input from becoming SQL. Request schemas reject unknown fields, blank text, malformed CVEs, invalid enums, and invalid scores. Transactions protect lifecycle changes. Passwords use salted PBKDF2-HMAC-SHA256 (600,000 iterations); only token hashes are stored.
- Errors use `{"status":"error","message":"..."}`; 401 authentication, 403 authorization, 404 missing record, 409 workflow/constraint conflict, 422 validation.

See `docs/REPORT.md`, the generated report DOCX, schema diagram, and API reference. See `docs/SUBMISSION-CHECKLIST.md` for requirements that need your own screenshots and your team's contributions. AI assistance is disclosed in the report. No fabricated history, screenshots, or teammate contributions are included.

To reproduce the Newman run after starting servers:

```sh
.venv/bin/python -m scripts.prepare_newman
npx --yes newman run postman/Services-7-8-9.postman_collection.json -e data/newman-local.postman_environment.json
```

Use `requirements-lock.txt` instead of `requirements.txt` to reproduce the exact tested Python dependency versions.
