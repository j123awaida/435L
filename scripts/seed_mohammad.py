"""Seed threat indicators for Services 4–6 demonstration without altering team records.

Threats cover every supported type and all four severity levels so the threat report shows
a meaningful distribution. Existing indicators are preserved: re-running changes nothing.
"""
from app.auth import now
from app.db import connect, initialize

THREATS = [
    ('IP Address', '198.51.100.24', 'Command-and-control host observed in outbound beaconing', 'Critical', 'Internal detection'),
    ('IP Address', '203.0.113.9', 'Repeated authentication failures against the VPN gateway', 'High', 'Firewall logs'),
    ('IP Address', '2001:db8::f00d', 'Scanning activity against the public subnet', 'Medium', 'Network sensor'),
    ('Domain', 'malicious-update.test', 'Phishing domain impersonating the software update portal', 'High', 'Threat feed'),
    ('Domain', 'tracker.example.test', 'Low-reputation domain contacted by a workstation', 'Low', 'DNS logs'),
    ('File Hash', 'd41d8cd98f00b204e9800998ecf8427e', 'Dropper sample recovered from an email attachment', 'Critical', 'Malware analysis'),
    ('File Hash', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'Credential stealer identified on a laptop', 'High', 'Endpoint agent'),
    ('Malware Signature', 'Trojan.Generic.KD.4471', 'Signature matching a banking trojan family', 'Medium', 'Antivirus vendor'),
    ('Other', 'Suspicious PowerShell encoded command', 'Attack indicator seen during incident triage', 'Medium', 'Analyst review'),
]


def main():
    initialize()
    added = 0
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        for threat_type, value, description, severity, source in THREATS:
            existing = db.execute('SELECT 1 FROM threats WHERE threat_type=? AND threat_value=?', (threat_type, value)).fetchone()
            if existing is None:
                db.execute('INSERT INTO threats(threat_type,threat_value,description,severity,source,created_at)'
                           ' VALUES(?,?,?,?,?,?)', (threat_type, value, description, severity, source, now()))
                added += 1
    print(f'Threat intelligence seed complete: {added} indicator(s) added, existing records retained.')
    print('Audit records are produced by live system activity; this seed does not fabricate them.')


if __name__ == '__main__':
    main()
