#!/usr/bin/env python3


import json, os
from pathlib import Path

TEMPLATE_IP = "SecurityAlert | where Entities has '{value}'"
TEMPLATE_DOMAIN = "DeviceNetworkEvents | where RemoteUrl =~ '{value}'"
TEMPLATE_HASH = "DeviceFileEvents | where SHA256 == '{value}' or SHA1 == '{value}'"

OUT = Path("out"); OUT.mkdir(exist_ok=True)

with open("iocs.json", "r") as f:
    data = json.load(f)

idx = 0
for item in data:
    idx += 1
    ioc_type = item.get("type", "").lower()
    value = item.get("value")
    if not value:
        continue
    if ioc_type == "ip":
        q = TEMPLATE_IP.format(value=value)
    elif ioc_type == "domain":
        q = TEMPLATE_DOMAIN.format(value=value)
    elif ioc_type in ("sha256", "sha1", "hash"):
        q = TEMPLATE_HASH.format(value=value)
    else:
        q = f"// unsupported IOC type: {ioc_type} value: {value}"
    (OUT / f"hunt_{idx:03d}.kql").write_text(q)
print(f"Generated {idx} queries in {OUT}")
