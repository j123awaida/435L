"""Run Hassan's Services 1–3. Optionally include Joseph's services and delivery worker."""
import argparse
import os
import signal
import subprocess
import sys
import time
from app.sprint123_models import PREFIX

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-joseph', action='store_true', help='Also run Services 7–9 and the shared notification delivery worker')
    args = parser.parse_args()
    services = [('app.users:app', 8000), ('app.assets:app', 8002), ('app.incidents:app', 8003)]
    if args.with_joseph:
        services += [('app.vulnerabilities:app', 8007), ('app.notifications:app', 8008), ('app.playbooks:app', 8009)]
    processes = []
    environment = os.environ | {'IDENTITY_LOGIN_URL': os.getenv('IDENTITY_LOGIN_URL', f'http://127.0.0.1:8000{PREFIX}/users/login')}
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        for module, port in services:
            processes.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', module, '--host', '127.0.0.1', '--port', str(port)], env=environment))
        if args.with_joseph:
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
