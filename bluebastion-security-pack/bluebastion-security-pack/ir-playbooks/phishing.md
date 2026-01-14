# IR Playbook: Suspected Phishing Email

**Goal:** Contain and analyze a suspected phishing email, coach the reporter, and improve controls.

## Entry criteria
- User reports suspicious email or automated alert flags a phish.

## Actions
1. **Triage**: Retrieve message trace, headers, and URLs.
2. **Contain**: Quarantine similar messages via Defender for O365.
3. **Hunt**: KQL pivots for URL/domain across mailboxes and endpoints.
4. **Coach**: Send micro-lesson link; thank reporter.
5. **Lessons learned**: Update allow/block lists; tune rules.

## Evidence checklist
- Original .eml, headers, URL detonation result, user reports.

## Closure criteria
- No remaining malicious copies; users informed; SIEM rules updated.
