import json
import re
from pathlib import Path
from datetime import datetime

SOURCE = Path("/var/log/cloud-network-firewall.log")
OUTPUT = Path("logs/firewall_verdicts.jsonl")

pattern = re.compile(
    r"CLOUD_NETWORK_FIREWALL: (ACCEPT|REJECT) .*?"
    r"\bSRC=(\S+) DST=(\S+).*?\bPROTO=(TCP|UDP|ICMP)"
    r"(?:.*?\bSPT=(\d+) DPT=(\d+))?"
)

count = 0
with SOURCE.open(encoding="utf-8", errors="replace") as source, \
     OUTPUT.open("w", encoding="utf-8") as output:
    for line in source:
        match = pattern.search(line)
        if not match:
            continue

        verdict, src, dst, protocol, sport, dport = match.groups()
        record = {
            "timestamp": line.split(" ", 1)[0],
            "source_ip": src,
            "destination_ip": dst,
            "protocol": protocol,
            "source_port": int(sport) if sport else None,
            "destination_port": int(dport) if dport else None,
            "action": verdict
        }
        output.write(json.dumps(record) + "\n")
        count += 1

print(f"Parsed {count} firewall verdicts.")
print(f"Saved to {OUTPUT}")
