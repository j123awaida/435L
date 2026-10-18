"""Durable Service 7 -> Service 8 HTTP delivery with idempotent retries."""
import hashlib
import json
import os
import uuid
import httpx
from .auth import now
from .db import connect


def enqueue_vulnerability_alert(db, record, recipient_id):
    payload = {
        'user_id': recipient_id,
        'title': f'Vulnerability discovered: {record["title"]}'[:2000],
        'message': f'{record["cve_identifier"]} affects asset {record["asset_id"]}; '
                   f'severity {record["severity"]}, CVSS {record["cvss_score"]}.',
        'notification_type': 'Vulnerability Alert',
        'severity': record['severity'],
    }
    db.execute('INSERT INTO notification_outbox(event_id,payload_json,created_at) VALUES(?,?,?)',
               (str(uuid.uuid4()), json.dumps(payload, sort_keys=True), now()))


class NotificationDelivery:
    """Injectable HTTP client; only a successful response acknowledges an event."""
    def __init__(self, client=None, endpoint=None):
        self.client = client or httpx.Client(timeout=5)
        self.endpoint = endpoint or os.getenv(
            'NOTIFICATIONS_API_URL', 'http://127.0.0.1:8008/Joseph-Awaida/notifications')

    def deliver(self, token, limit=100):
        with connect() as db:
            events = [dict(x) for x in db.execute(
                "SELECT * FROM notification_outbox WHERE status='Pending' ORDER BY created_at LIMIT ?", (limit,))]
        delivered = 0
        for event in events:
            try:
                response = self.client.post(
                    self.endpoint, json=json.loads(event['payload_json']),
                    headers={'Authorization': f'Bearer {token}', 'Idempotency-Key': event['event_id']})
                response.raise_for_status()
            except httpx.HTTPError as error:
                # Persist only the error category/status, never response bodies or tokens.
                message = (f'HTTP {error.response.status_code}' if isinstance(error, httpx.HTTPStatusError)
                           else type(error).__name__)
                with connect() as db:
                    db.execute('UPDATE notification_outbox SET attempts=attempts+1,last_error=? WHERE event_id=?',
                               (message, event['event_id']))
            else:
                with connect() as db:
                    db.execute("UPDATE notification_outbox SET status='Delivered',attempts=attempts+1,last_error=NULL,delivered_at=? WHERE event_id=?",
                               (now(), event['event_id']))
                delivered += 1
        return delivered

    def close(self):
        self.client.close()


def payload_digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
