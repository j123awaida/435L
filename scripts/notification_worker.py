"""Retry vulnerability alerts over the real Notification service HTTP API."""
import argparse
import json
import os
import time
from pathlib import Path
import httpx
from app.integration import NotificationDelivery
from app.db import initialize


def credentials():
    username = os.getenv('SERVICE_USERNAME', 'admin')
    password = os.getenv('SERVICE_PASSWORD')
    if not password:
        password = json.loads(Path('data/demo-credentials.json').read_text())[username]
    return {'username': username, 'password': password}


def main(once=False):
    initialize()
    delivery = NotificationDelivery()
    token = None
    refresh_at = 0
    try:
        while True:
            try:
                if token is None or time.time() >= refresh_at:
                    with httpx.Client(timeout=5) as client:
                        response = client.post(os.getenv('IDENTITY_LOGIN_URL', 'http://127.0.0.1:8000/Joseph-Awaida/auth/login'), json=credentials())
                        response.raise_for_status()
                        token = response.json()['access_token']
                        refresh_at = time.time() + 3000
                count = delivery.deliver(token)
                if count:
                    print(f'Delivered {count} vulnerability alerts through Service 8.', flush=True)
            except (httpx.HTTPError, OSError, KeyError, ValueError):
                # Tokens and passwords are never logged. Pending events remain retryable.
                print('Notification delivery unavailable; pending events retained.', flush=True)
            if once:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        delivery.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true')
    main(once=parser.parse_args().once)
