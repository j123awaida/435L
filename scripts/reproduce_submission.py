"""Reproduce public validation/report artifacts from this contribution."""
import subprocess
import sys
import time
from pathlib import Path
import httpx

ROOT=Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(args,cwd=ROOT,check=True)


def running():
    states=[]
    for port in (8000,8007,8008,8009):
        try:
            response=httpx.get(f'http://127.0.0.1:{port}/Joseph-Awaida/health',timeout=1)
            states.append(response.status_code==200)
        except httpx.HTTPError:
            states.append(False)
    return states


def main():
    python=sys.executable
    run(python,'-m','scripts.seed')
    runner=None
    states=running()
    if any(states) and not all(states):
        raise SystemExit('Only some API ports are available. Stop the incomplete local runner and retry.')
    try:
        if not all(states):
            # A new process group allows cleanup of only this script's own processes.
            runner=subprocess.Popen([python,'-m','scripts.run'],cwd=ROOT,start_new_session=True)
            for _ in range(40):
                if all(running()):
                    break
                if runner.poll() is not None:
                    raise RuntimeError('Local services failed to start')
                time.sleep(.25)
            else:
                raise RuntimeError('Local service startup timed out')
        run(python,'-m','pytest','-q','--junitxml=evidence/pytest-results.xml')
        run(python,'-m','scripts.generate_artifacts')
        run(python,'-m','scripts.capture_evidence')
        run(python,'-m','scripts.verify_integration')
        run(python,'-m','scripts.prepare_newman')
        with (ROOT/'evidence/newman-output.txt').open('w') as output:
            subprocess.run(['npx','--yes','newman','run','postman/Services-7-8-9.postman_collection.json','-e','data/newman-local.postman_environment.json','--reporters','cli,json','--reporter-cli-no-console','--reporter-json-export','data/newman-private-report.json'],cwd=ROOT,stdout=output,check=True)
        run(python,'-m','scripts.validation_summary')
        run(python,'-m','scripts.diagrams')
        run(python,'-m','scripts.generate_artifacts')
        run(python,'-m','scripts.pdf_report')
        run(python,'-m','scripts.package_submission')
    finally:
        if runner is not None:
            import os
            import signal
            try:
                os.killpg(runner.pid,signal.SIGTERM)
            except ProcessLookupError:
                pass
            runner.wait(timeout=15)

if __name__=='__main__':
    main()
