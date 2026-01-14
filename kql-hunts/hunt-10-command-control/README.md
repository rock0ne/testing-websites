# Hunt 10: Command & Control Detection

## Goal
Detect command and control (C2) communications including beaconing, DNS tunneling, and encrypted channels.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1071 | Application Layer Protocol |
| T1071.001 | Web Protocols |
| T1071.004 | DNS |
| T1573 | Encrypted Channel |
| T1571 | Non-Standard Port |
| T1090 | Proxy |

## Detection Categories

| Category | Severity | Indicators |
|----------|----------|------------|
| Beaconing | Critical | Regular interval connections |
| DNS C2 | High | Long/encoded DNS queries |
| Non-standard ports | Medium | Encrypted traffic on unusual ports |
| Known C2 | Critical | Cobalt Strike, Metasploit indicators |
| Suspicious UA | Medium | Unusual or missing User-Agent |

## Beaconing Detection Logic

The query calculates:
- Average interval between connections
- Standard deviation of intervals
- Low variance (< 30% of average) indicates automated beaconing

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Legitimate software updates | Whitelist known update servers |
| Cloud services | Baseline normal cloud traffic |
| Monitoring agents | Exclude known monitoring tools |

## Response Actions

1. **Block**: Add C2 IPs to firewall blocklist
2. **Isolate**: Quarantine affected endpoint
3. **Investigate**: Analyze full process chain
4. **Hunt**: Search for similar activity across environment
5. **Remediate**: Remove malware and persistence
