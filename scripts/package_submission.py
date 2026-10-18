"""Package only source and public artifacts; never local secrets or duplicate extracts."""
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / 'Joseph-Awaida-Services-7-8-9-Sprint-I.zip'


def package():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    files = [ROOT / name for name in names if name and (ROOT / name).is_file()]
    private = ROOT / 'data/demo-credentials.json'
    secrets = json.loads(private.read_text()).values() if private.exists() else []
    for file in files:
        data = file.read_bytes()
        if any(value.encode() in data for value in secrets):
            raise SystemExit(f'Refusing to package a development password in {file.relative_to(ROOT)}')
        if any(part in ('data', '.venv', '.git', '__pycache__') for part in file.relative_to(ROOT).parts):
            raise SystemExit('Refusing to package private/runtime data')
    with zipfile.ZipFile(ARCHIVE, 'w', zipfile.ZIP_DEFLATED) as output:
        for file in files:
            output.write(file, arcname='Joseph-Awaida-Services-7-8-9/' + str(file.relative_to(ROOT)))
    print(f'Created {ARCHIVE.name}: {len(files)} files, {ARCHIVE.stat().st_size:,} bytes.')
    print('SHA-256: ' + hashlib.sha256(ARCHIVE.read_bytes()).hexdigest())

if __name__ == '__main__':
    package()
