"""Build the common Moodle submission, excluding secrets and redundant individual reports."""
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
NAME='Hassan-Nasrallah-Mohammad-Nasrallah-Joseph-Awaida-430L'


def main():
    tracked=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
    paths={ROOT/name for name in tracked if name}
    for relative in ('docs/team','database','evidence/team'):
        paths.update(p for p in (ROOT/relative).rglob('*') if p.is_file())
    paths.update([ROOT/'GitHub-Repository.txt',ROOT/'SUBMIT-ON-MOODLE.md'])
    omitted={'docs/Joseph-Awaida-Sprint-I-Report.docx','docs/Joseph-Awaida-Sprint-I-Report.pdf'}
    files=[]
    secrets=[]
    for source in (ROOT/'data/demo-credentials.json',ROOT/'data/team-runtime/data/demo-credentials.json'):
        if source.exists():secrets.extend(json.loads(source.read_text()).values())
    for path in sorted(paths):
        if not path.is_file():continue
        name=str(path.relative_to(ROOT))
        if name in omitted or path.suffix=='.zip':continue
        if any(part in ('data','.venv','.git','__pycache__','.pytest_cache') for part in Path(name).parts):
            raise SystemExit('Private or runtime data would enter archive: '+name)
        if any(secret.encode() in path.read_bytes() for secret in secrets):
            raise SystemExit('A development password would enter archive: '+name)
        files.append((path,name))
    required=['app/users.py','app/assets.py','app/incidents.py','app/threats.py','app/logs.py','app/reports.py','app/vulnerabilities.py','app/notifications.py','app/playbooks.py','database/schema.sql','docs/team/FINAL-TEAM-REPORT.docx','docs/team/FINAL-TEAM-REPORT.pdf','postman/Team-All-Services.postman_collection.json']
    present={name for _,name in files}
    assert set(required)<=present,set(required)-present
    target=ROOT/(NAME+'.zip')
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
        for path,name in files:archive.write(path,arcname=NAME+'/'+name)
        manifest={name:hashlib.sha256(path.read_bytes()).hexdigest() for path,name in files}
        archive.writestr(NAME+'/SUBMISSION-MANIFEST.json',json.dumps(manifest,indent=2))
    with zipfile.ZipFile(target) as archive:assert archive.testzip() is None
    print(f'Final team ZIP: {target.name}')
    print(f'{len(files)+1} files; {target.stat().st_size:,} bytes; archive integrity verified.')
    print('SHA-256: '+hashlib.sha256(target.read_bytes()).hexdigest())

if __name__=='__main__':
    main()
