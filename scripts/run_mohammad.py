"""Run Mohammad Nasrallah's Services 4–6. Optionally include the teammate services they report on."""
import argparse
import os
import signal
import subprocess
import sys
import time
from app.sprint123_models import PREFIX as HASSAN
from app.sprint456_models import PREFIX as MINE

JOSEPH = '/Joseph-Awaida'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-team', action='store_true',
                        help="Also run Hassan's Services 1–3 and Joseph's Services 7–9 so Service 6 collects over HTTP")
    args = parser.parse_args()
    services = [('app.threats:app', 8004), ('app.logs:app', 8005), ('app.reports:app', 8006)]
    if args.with_team:
        services = [('app.users:app', 8000), ('app.assets:app', 8002), ('app.incidents:app', 8003)] + services + \
                   [('app.vulnerabilities:app', 8007), ('app.notifications:app', 8008), ('app.playbooks:app', 8009)]
    # Service 6 reads these to locate each source; defaults already match the local ports.
    environment = os.environ | {
        'IDENTITY_LOGIN_URL': os.getenv('IDENTITY_LOGIN_URL', f'http://127.0.0.1:8000{HASSAN}/users/login'),
        'USERS_API_URL': os.getenv('USERS_API_URL', f'http://127.0.0.1:8000{HASSAN}/users'),
        'ASSETS_API_URL': os.getenv('ASSETS_API_URL', f'http://127.0.0.1:8002{HASSAN}/assets'),
        'INCIDENTS_API_URL': os.getenv('INCIDENTS_API_URL', f'http://127.0.0.1:8003{HASSAN}/incidents'),
        'THREATS_API_URL': os.getenv('THREATS_API_URL', f'http://127.0.0.1:8004{MINE}/threats'),
        'LOGS_API_URL': os.getenv('LOGS_API_URL', f'http://127.0.0.1:8005{MINE}/logs'),
        'VULNERABILITIES_API_URL': os.getenv('VULNERABILITIES_API_URL', f'http://127.0.0.1:8007{JOSEPH}/vulnerabilities'),
    }
    processes = []

    def stop(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        for module, port in services:
            processes.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', module, '--host', '127.0.0.1',
                                               '--port', str(port)], env=environment))
        if args.with_team:
            processes.append(subprocess.Popen([sys.executable, '-m', 'scripts.notification_worker'], env=environment))
        while all(p.poll() is None for p in processes):
            time.sleep(.5)
        raise RuntimeError('A service exited; inspect the server output')
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            process.wait()


if __name__ == '__main__':
    main()
