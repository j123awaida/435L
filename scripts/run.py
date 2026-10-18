"""Run three independent service processes and the temporary identity adapter."""
import subprocess
import sys
import signal
import time

services=[('app.common:app',8000),('app.vulnerabilities:app',8007),('app.notifications:app',8008),('app.playbooks:app',8009)]
processes=[]
def stop(signum, frame):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, stop)
try:
    for module,port in services:
        processes.append(subprocess.Popen([sys.executable,'-m','uvicorn',module,'--host','127.0.0.1','--port',str(port)]))
    processes.append(subprocess.Popen([sys.executable, '-m', 'scripts.notification_worker']))
    while all(p.poll() is None for p in processes):
        time.sleep(.5)
except KeyboardInterrupt:
    pass
finally:
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        p.wait()
