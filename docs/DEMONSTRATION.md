# Demonstrating services 7–9 (Joseph Awaida)

## Start and authenticate

Run the commands in README.md. Passwords are generated locally in `data/demo-credentials.json`; use them only locally. Import the Postman collection/environment. Enter each role's password in its secret environment variable, select the environment, and run the four login requests. The collection saves tokens automatically.

## Explain your implementation

1. **Vulnerability lifecycle:** create a record against asset 1. Try `Open → Closed` and explain the 409. Advance through every allowed state and show the resolution date generated at Resolved. Show exact filters for CVE, severity, asset, and status.
2. **Notification privacy:** create an alert for employee 3. Read it as employee 3, then try the analyst token against that alert and show 403. Mark it read twice; the first read timestamp stays unchanged. An auditor may read/search but cannot mark read.
3. **Response workflow:** create a playbook, add steps 1 and 2, and try starting step 2 first. Show 409, complete step 1, then complete step 2. Retrieve the playbook and its execution history. Delete it as administrator; historical rows remain in the database.
4. **HTTP communication:** create a vulnerability and show the corresponding Vulnerability Alert for the asset owner. Inspect the delivered outbox row. Retry the same event id to show duplicate protection.
5. **Authentication:** explain PBKDF2 password hashing, random bearer tokens, token hashes, expiry, and current account-status checks. Explain why a caller cannot supply a role through a request body.
6. **SQL safety:** values are bound through `?` parameters. Body fields are checked against Pydantic models; malformed CVEs, invalid enums, blank text, and unsupported fields are rejected.
7. **Audit/history:** successful changes and permission denials are recorded. Playbook execution history is append-only and survives deletion. The current audit table is the integration boundary for teammate Service 5.

## Genuine screenshot capture

Run the Postman folders in order. For each request, show the method, `/Joseph-Awaida/...` route, applicable request body, HTTP status, and response. Screenshot successful and rejected requests. Caption every figure with “Joseph Awaida — [request name]: [what it demonstrates]”. Do not expose passwords or raw bearer tokens.

Useful database queries (use a SQLite client against `data/security.sqlite3`):

```sql
SELECT name, sql FROM sqlite_master WHERE type='table';
SELECT * FROM vulnerabilities;
SELECT * FROM notifications;
SELECT * FROM playbooks;
SELECT * FROM actions ORDER BY playbook_id, step_number;
SELECT * FROM action_history ORDER BY id;
SELECT * FROM notification_outbox;
SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30;
```

Capture before/after records before the collection deletes demonstration objects. `evidence/database-transitions.json` retains actual before/after records for replay review, but it is not a screenshot.

Access was subsequently enabled and genuine screenshots were captured. See evidence/screenshots and the report appendices. Images were not edited. Authentication screenshots omit bearer-token responses and private resolved passwords; full ordinary request/response views are captured. JSON records and generated design diagrams remain supplemental artifacts, not screenshots.
