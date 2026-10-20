# Security Incident Detection and Response

## Hassan Nasrallah — Sprint I, Services 1–3

Users/identity, assets, and incidents are implemented on Hassan's contribution branch. See [Hassan's setup, API reference and team handoff](docs/HASSAN-SPRINT1.md).

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-lock.txt
.venv/Scripts/python.exe -m scripts.seed_hassan
.venv/Scripts/python.exe -m scripts.run_hassan --with-joseph
```

Hassan's APIs use `/Hassan-Nasrallah`: identity on port **8000**, assets on **8002**, incidents on **8003**. Each process has `/docs`. The optional `--with-joseph` starts Services 7–9 and the notification delivery worker. The original `scripts.run` below remains available for Joseph's standalone contribution; the two runners both use port 8000, so run one at a time.

Import `postman/Hassan-Services-1-2-3.postman_collection.json` and `postman/Hassan-Local.postman_environment.json`. Set local role passwords from the ignored `data/demo-credentials.json` and run the folders in order. All team services accept the opaque bearer tokens issued by Hassan's identity service.

## Mohammad Nasrallah — Sprint I, Services 4–6

Threat intelligence, security audit logging and security reports are implemented on Mohammad's contribution branch, which builds on Hassan's. See [Mohammad's setup, API reference and team handoff](docs/MOHAMMAD-SPRINT1.md).

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-lock.txt
.venv/Scripts/python.exe -m scripts.seed_hassan
.venv/Scripts/python.exe -m scripts.seed_mohammad
.venv/Scripts/python.exe -m scripts.run_mohammad --with-team
```

Mohammad's APIs use `/Mohammad-Nasrallah`: threats on port **8004**, audit logs on **8005**, reports on **8006**. Each process has `/docs`. The optional `--with-team` also starts Hassan's Services 1–3 and Joseph's Services 7–9, which Service 6 collects from over HTTP; without it, Service 6 falls back to reading the shared database and says so in each report's `sources` block. All three runners use overlapping ports, so run one at a time.

Import `postman/Mohammad-Services-4-5-6.postman_collection.json` and `postman/Mohammad-Local.postman_environment.json`, set the role passwords from the ignored `data/demo-credentials.json`, and run the folders in order. Authentication uses Hassan's Service 1 on port 8000.

Service 5 exposes an idempotent audit log ingestion endpoint for teammate services: see [the Service 5 integration contract](docs/MOHAMMAD-SERVICE5-INTEGRATION.md).

## Joseph Awaida — Sprint I, Services 7–9

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

See `evidence/validation-summary.json` and `evidence/SUMMARY.md` for actual test and Postman Newman results. `evidence/http-integration.json` records real Service 7 → Service 8 alert delivery and duplicate protection.

Start the servers before capturing evidence. The capture script executes real HTTP calls against the local processes and saves sanitized responses, a database snapshot, and the live OpenAPI specifications in `evidence/`. It deliberately retains demo records for inspection. Re-running it creates additional records. Automated HTTP evidence does not replace the required Postman screenshots.

Import `postman/Services-7-8-9.postman_collection.json` and its environment into Postman. Set passwords from the local credentials file, then run the login requests to populate token variables. Run folders in order. Capture real Postman requests/responses with captions identifying **Joseph Awaida**, operation, and purpose. Never include bearer tokens or passwords in public screenshots.

## Integration with teammates

The identity adapter, minimal users/assets reference tables, and local audit table are integration scaffolding for Services 1, 2, and 5; they are not complete implementations of teammates' services. All four processes currently use the same SQLite file (configurable through `DATABASE_PATH`), so ownership and foreign keys are enforced locally. They expose independent HTTP APIs. Replace the scaffolding with the team's identity verification, asset lookup, and audit API adapters when those contracts are supplied. Audit permission denials currently persist locally; forwarding to Service 5 remains a team integration task. Upstream services can create alerts through the administrator-authenticated Service 8 HTTP endpoint. Service 7 automatically queues alerts for asset owners, and a worker delivers them to Service 8 over HTTP with retry and idempotency protection. No automatic incident/threat event producer is included in this contribution.

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

## Final contribution artifacts

- `docs/Joseph-Awaida-Sprint-I-Report.docx`: editable contribution report.
- `docs/Joseph-Awaida-Sprint-I-Report.pdf`: paginated report with table of contents and execution/database appendix.
- `docs/TEAM-INTEGRATION.md`: notification contract and teammate interfaces.
- `docs/DEMONSTRATION.md`: walkthrough and genuine screenshot instructions.
- `scripts/package_submission.py`: package committed public files, excluding private credentials.

The local runner also starts a retry worker. Automatic vulnerability alerts are delivered to the affected asset owner; check their notifications and `notification_outbox` delivery status. `Idempotency-Key` on notification creation prevents duplicate delivery.

To reproduce the whole contribution package (requires Python dependencies and Node/npm):

```sh
.venv/bin/python -m scripts.reproduce_submission
```

This command uses existing local servers when all four are running, otherwise starts its own processes. It executes actual tests/requests, rebuilds reports and packages public files. It creates additional demonstration records. It does not capture desktop screenshots, submit to Moodle, or publish Git changes.

## Genuine screenshot evidence

The report appendices embed unedited Postman desktop runner captures, real read-only database views and GitHub commit history. Metadata and individual PNGs are in `evidence/screenshots/`. Authentication response bodies containing tokens and private resolved password bodies are omitted from public screenshots.

Optional reproduction tools: install `requirements-evidence.txt`, run `.venv/bin/sqlite_web -r -x -p 8010 data/security.sqlite3`, then `.venv/bin/python -m scripts.capture_browser_evidence`. For Postman, launch the desktop app with `ELECTRON_RUN_AS_NODE` removed, run the imported collection in the authorized environment, and execute `node scripts/capture_postman_evidence.mjs <local-debug-port>`. The scripts capture real running applications, not generated facsimiles.
