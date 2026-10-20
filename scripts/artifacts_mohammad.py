"""Export OpenAPI documentation for Mohammad Nasrallah's Services 4–6.

Generated schemas are API documentation, not execution evidence: the required Postman
screenshots must still come from a real run against the live services.

    python -m scripts.artifacts_mohammad
"""
import json
import os
import tempfile
from pathlib import Path

# Importing the applications must never touch the team database.
os.environ.setdefault('DATABASE_PATH', str(Path(tempfile.mkdtemp()) / 'artifacts.sqlite3'))

from app.logs import app as logs_app          # noqa: E402
from app.reports import app as reports_app    # noqa: E402
from app.threats import app as threats_app    # noqa: E402

OUTPUT = Path('docs/mohammad')
SERVICES = [('service-4', threats_app), ('service-5', logs_app), ('service-6', reports_app)]


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, app in SERVICES:
        path = OUTPUT / f'{name}.openapi.json'
        schema = app.openapi()
        path.write_text(json.dumps(schema, indent=2) + '\n', encoding='utf8')
        routes = sum(len(methods) for methods in schema['paths'].values())
        print(f'Wrote {path} ({app.title}, {routes} documented operations)')


if __name__ == '__main__':
    main()
