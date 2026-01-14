# bluebastion-security-pack

A defender-first **security portfolio** for threat hunting, detection engineering, IR playbooks, API security, and platform hardening.

> **Safety note:** This repository avoids bypass/evasion content. All exercises are for **authorized lab use** and focus on **prevention, detection, and response**.

## Contents
- `hunts/` – KQL threat hunting queries with synthetic test data.
- `detections/` – Sentinel/Defender analytics rules, tests, and coverage.
- `ir-playbooks/` – Incident response guides and automation outlines.
- `api-sec/` – Secure sample API (JWT/OAuth2.1), tests, and ASVS/WSTG checklists.
- `intune/` – Intune/Defender ASR baselines and validation queries.
- `intel-to-detections/` – Scripts to transform IOCs into hunts.
- `ad-detections/` – AD hardening checklist and ATT&CK-mapped detections.
- `brand/` – Career narratives (STAR) and LinkedIn summary templates.

## MITRE ATT&CK coverage
See `detections/coverage.csv`.

## Getting started
```bash
# optional: create and activate a venv for API/tests/tools
python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -r api-sec/requirements.txt
```

## Contributing
See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
