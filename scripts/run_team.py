"""Run all nine team services with one identity service and the notification worker."""
import argparse
import os
import signal
import subprocess
import sys
import time

SERVICES=[('app.users:app',0),('app.assets:app',2),('app.incidents:app',3),('app.threats:app',4),
          ('app.logs:app',5),('app.reports:app',6),('app.vulnerabilities:app',7),
          ('app.notifications:app',8),('app.playbooks:app',9)]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-port',type=int,default=8000)
    args=parser.parse_args()
    if not 1024<=args.base_port<=65526:
        parser.error('--base-port must be between 1024 and 65526')
    base=args.base_port
    endpoints={
        'IDENTITY_LOGIN_URL':(0,'Hassan-Nasrallah/users/login'),
        'USERS_API_URL':(0,'Hassan-Nasrallah/users'),'ASSETS_API_URL':(2,'Hassan-Nasrallah/assets'),
        'INCIDENTS_API_URL':(3,'Hassan-Nasrallah/incidents'),'THREATS_API_URL':(4,'Mohammad-Nasrallah/threats'),
        'LOGS_API_URL':(5,'Mohammad-Nasrallah/logs'),'VULNERABILITIES_API_URL':(7,'Joseph-Awaida/vulnerabilities'),
        'NOTIFICATIONS_API_URL':(8,'Joseph-Awaida/notifications'),
    }
    environment=os.environ|{key:f'http://127.0.0.1:{base+offset}/{path}' for key,(offset,path) in endpoints.items()}
    processes=[]
    def stop(signum,frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    try:
        for module,offset in SERVICES:
            processes.append(subprocess.Popen([sys.executable,'-m','uvicorn',module,'--host','127.0.0.1','--port',str(base+offset)],env=environment))
        processes.append(subprocess.Popen([sys.executable,'-m','scripts.notification_worker'],env=environment))
        while all(p.poll() is None for p in processes):
            time.sleep(.5)
        raise RuntimeError('A team service exited; inspect its output and check for occupied ports.')
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            process.wait()

if __name__=='__main__':
    main()
