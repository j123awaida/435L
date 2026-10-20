# Evidence capture checklist — Services 4–6 (Mohammad Nasrallah)

The brief requires every screenshot to come from **your own running system**. Generated or simulated screenshots are not valid evidence, and screenshots of source code do not count as proof of functionality. This checklist tells you exactly what to capture; the capturing has to be done by you.

Caption every screenshot in this form:

> **Mohammad Nasrallah — <operation> — <what it demonstrates>**

Example: *Mohammad Nasrallah — POST /threats — adds a critical malicious IP indicator and returns the stored record.*

**Never include** a password, an `Authorization` header value, or a login token response in a submitted screenshot. In Postman, collapse the Authorization header row or blur the token before capturing. The login requests store tokens into collection variables automatically, so you do not need to show them.

## Before you start

```powershell
.venv/Scripts/python.exe -m scripts.seed_hassan
.venv/Scripts/python.exe -m scripts.seed_mohammad
.venv/Scripts/python.exe -m scripts.run_mohammad --with-team
```

Then in Postman: import `postman/Mohammad-Services-4-5-6.postman_collection.json` and `postman/Mohammad-Local.postman_environment.json`, select the environment, and fill the four role passwords from `data/demo-credentials.json`. Run folder **0. Authentication** first so the role tokens are populated.

Run the folders in order (0 → 1 → 2 → 3). Several requests depend on identifiers captured by earlier ones.

## Service 4 — Threat Intelligence

| # | Request | Must show |
| --- | --- | --- |
| 1 | Add threat indicator — IP address | Request body and 201 response with the stored record |
| 2 | Add threat indicator — Domain | 201, a different type and severity |
| 3 | Add threat indicator — File hash | 201, a third type and severity |
| 4 | Add duplicate indicator | 409 — duplicate type/value prevented |
| 5 | Add indicator with an invalid IP | 422 and the `errors` array naming the field |
| 6 | Add indicator with an invalid hash | 422 — hash format validation |
| 7 | Add indicator with an invalid severity | 422 — enum validation |
| 8 | Add indicator as analyst | 403 — only administrators may add |
| 9 | Add indicator without a token | 401 — authentication required |
| 10 | Retrieve all indicators | 200 with severity, source and date added |
| 11 | Retrieve all indicators as employee | 403 — no employee access |
| 12 | Retrieve a specific indicator | 200 for an existing record |
| 13 | Retrieve a non-existing indicator | 404 and the shared error shape |
| 14 | Search by threat type | 200, filtered results |
| 15 | Search by severity | 200, filtered results |
| 16 | Search by partial value | 200 — substring matching |
| 17 | Search by source and type combined | 200 — filters combine with AND |
| 18 | Search with no matches | 200 and an empty array |
| 19 | Update indicator severity and source | **Capture requests 12 and 19 as before/after** |
| 20 | Update threat value | 422 — type and value are immutable |
| 21 | Delete indicator as auditor | 403 — unauthorized deletion prevented |
| 22 | Delete indicator as administrator | 200 — authorized deletion |

Also capture: the `threats` table structure and its stored rows (requirement: show the created records in the database), and an explanation of the type and severity of each indicator you added.

## Service 5 — Security Audit Logging

| # | Request | Must show |
| --- | --- | --- |
| 23 | Create log record | 201 with the generated timestamp |
| 24 | Create log with an Idempotency-Key | 201 — first delivery |
| 25 | Replay the same Idempotency-Key | **200 and the same `id`** — no duplicate created |
| 26 | Reuse the key with a different payload | 409 — key already bound to another event |
| 27 | Create log with an invalid severity | 422 — enum validation |
| 28 | Create log for an unknown user | 422 — referenced user must exist |
| 29 | Create log as analyst | 403 — only administrators may write |
| 30 | Retrieve all logs | 200 — include rows produced automatically by earlier activity |
| 31 | Retrieve all logs as auditor | 200 — auditor read access |
| 32 | Retrieve all logs as analyst | 403 — analysts cannot list all logs |
| 33 | Retrieve all logs as employee | 403 — no employee access |
| 34 | Retrieve a specific log | 200 |
| 35 | Retrieve an invalid log id | 404 |
| 36 | Search logs by severity | 200 — `Warning` shows failed logins and denials |
| 37 | Search logs by action | 200 — substring matching |
| 38 | Search logs by user and date | 200 — filters combine with AND |
| 39 | Search logs with no matches | 200 and an empty array |
| 40 | Retrieve logs by user | 200, all rows belonging to that user |
| 41 | Retrieve logs for a user with no activity | 200 and an empty array — **run this before generating employee activity** |
| 42 | Retrieve logs for an unknown user | 404 |
| 43 | Delete log as analyst | 403 |
| 44 | Delete log as auditor | 403 |
| 45 | Delete log as administrator | 200 — authorized deletion |

Also capture:

- The `audit_logs` table structure and rows, including records generated automatically by your login attempts and the 403 denials above — this evidences the mandatory automatic logging.
- The `log_receipts` row for the idempotent event, showing one receipt bound to one log.
- The `log_tombstones` row created by request 45.
- A failed login from folder 0 and the resulting `Login failed` record, which the activity report then counts.

For the "logs cannot be modified" requirement: there is no update endpoint, so show that `PUT /logs/{id}` returns **405 Method Not Allowed**, and optionally run `UPDATE audit_logs SET description='x' WHERE id=1;` in your SQLite tool to show the trigger aborting with *Audit logs are immutable*.

## Service 6 — Security Reports

| # | Request | Must show |
| --- | --- | --- |
| 46 | Generate security summary report | 200, totals and the `sources` block |
| 47 | Generate incident report | 200, totals by severity and status |
| 48 | Generate asset report | 200, totals, critical assets, by type |
| 49 | Generate threat report | 200, by severity and type, recent indicators |
| 50 | Generate vulnerability report | 200, by severity and status, critical count |
| 51 | Generate activity report | 200, login attempts, failures, most performed actions |
| 52 | Generate summary report as auditor | 200 — auditor may generate reports |
| 53 | Generate summary report as analyst | 403 — no analyst report access |
| 54 | Generate summary report as employee | 403 — no employee access |
| 55 | Generate summary report without a token | 401 |

**The brief requires you to verify report totals against the database.** For each report, capture the matching SQL count beside the response:

```sql
SELECT COUNT(*) FROM users WHERE id NOT IN (SELECT user_id FROM deleted_users);
SELECT COUNT(*) FROM assets;
SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Under Investigation','Mitigated');
SELECT severity, COUNT(*) FROM threats GROUP BY severity;
SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type;
SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity;
SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status;
SELECT action, COUNT(*) FROM audit_logs GROUP BY action ORDER BY COUNT(*) DESC;
```

The `sources` block in each response is how you evidence "explain how information is collected from other services": with all services running, every entry shows `"origin": "api"` and the URL it was collected from. To additionally demonstrate resilience, stop Service 2 (port 8002), re-run the asset report, and capture the response showing `"origin": "database"` with the reason — that one screenshot shows both collection paths.

## Database and version control evidence

- Schema diagram covering `threats`, `audit_logs`, `log_receipts` and `log_tombstones` and their relationships (the ER diagram in `MOHAMMAD-SPRINT1.md` is a starting point, but the submitted diagram should be yours).
- Screenshots of each table's structure and its stored records.
- Your GitHub commit history on `mohammad/sprint-1-services-4-6`, and the contributors view showing your commits distinctly from Hassan's and Joseph's.

## Not covered by this checklist

- The **CREATES coaching session** must be booked and attended by all three of you at least three days before the final deadline, and it is graded.
- The **shared final report** is team work. `MOHAMMAD-SPRINT1.md` supplies the content for the sections attributed to you, including the required AI-use disclosure.
- Hassan's and Joseph's screenshots are their evidence, not yours. The existing files under `evidence/screenshots/` belong to Joseph's Services 7–9.
