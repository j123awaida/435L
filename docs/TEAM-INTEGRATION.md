# Services 7–9 integration handoff (Joseph Awaida)

Joseph owns vulnerabilities, notifications, playbooks/actions, and execution history. The local identity adapter and reference users/assets are provided only to run and demonstrate this contribution independently.

## APIs exposed to teammates

All routes include `/Joseph-Awaida`. Service 7 is on port 8007, Service 8 on 8008, Service 9 on 8009. OpenAPI documents are in `docs/` and each process exposes `/docs`.

Upstream incident, threat, and system-event services can call:

```http
POST /Joseph-Awaida/notifications
Authorization: Bearer <administrator-or-approved-service-session>
Idempotency-Key: <unique-event-id>
Content-Type: application/json
```

```json
{
  "user_id": 2,
  "title": "Incident assigned",
  "message": "Investigate incident 42.",
  "notification_type": "Incident Assignment",
  "severity": "High"
}
```

Allowed notification types: Incident Assignment, Security Alert, System Notification, Threat Alert, Vulnerability Alert. Allowed severity values: Low, Medium, High, Critical. The optional idempotency key returns the original creation response on repeated identical payloads; reuse with another payload returns 409. This also prevents re-creation after a delivered notification is deleted.

## Actual communication within Joseph's services

Creating a vulnerability transactionally adds a `Vulnerability Alert` for its affected asset's owner to `notification_outbox`. A worker authenticates with the identity login endpoint and delivers the payload to Service 8 using HTTP and an idempotency key. Failed deliveries remain pending for retry. No credentials are stored in outbox rows. The database commit succeeds even when Service 8 is temporarily unavailable.

`scripts.run` starts the worker automatically. For an explicit retry:

```sh
.venv/bin/python -m scripts.notification_worker --once
```

Configuration variables:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_PATH` | `data/security.sqlite3` | Shared local demonstration database |
| `NOTIFICATIONS_API_URL` | `http://127.0.0.1:8008/Joseph-Awaida/notifications` | Alert delivery target |
| `IDENTITY_LOGIN_URL` | `http://127.0.0.1:8000/Joseph-Awaida/auth/login` | Worker login endpoint |
| `SERVICE_USERNAME` | `admin` | Local development identity used by the worker |
| `SERVICE_PASSWORD` | Read from ignored demo credentials file | Worker credential |

## Contracts still needed from teammates

- **Service 1:** agree token verification, current user lookup, account status and role mapping. Local roles are `admin`, `analyst`, `employee`, `auditor`. Local tokens are opaque, one-hour sessions; replacing authentication requires matching the team's contract.
- **Service 2:** agree asset lookup and asset owner identifiers. The local `assets(id,name,owner_id)` table is a reference boundary, not the complete asset service.
- **Service 5:** successful modifications and permission denials are persisted in `audit_logs`. Agree the team's authenticated log-creation endpoint and reliable forwarding mechanism. Remote audit forwarding is not claimed as implemented.
- **Services 3 and 4:** invoke the notification API for assignments and threat alerts; these event producers are teammates' responsibility.
- **Service 6:** read agreed endpoints or team-authorized database views for vulnerability statistics. No reports service is added to Joseph's contribution.

Teammate names, code, endpoint contracts, and contribution history have not been supplied. No teammate implementation or contribution is attributed to Joseph or fabricated.
