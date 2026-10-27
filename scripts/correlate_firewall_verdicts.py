import json
from pathlib import Path
from datetime import datetime

PACKETS = Path("logs/network_flows.jsonl")
VERDICTS = Path("logs/firewall_verdicts.jsonl")
OUTPUT = Path("logs/network_flows_with_verdicts.jsonl")

def load_jsonl(path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

packets = load_jsonl(PACKETS)
verdicts = load_jsonl(VERDICTS)

for packet in packets:
    packet["action"] = "PENDING_VERDICT"
    packet["verdict_source"] = None

    packet_time = datetime.fromisoformat(packet["timestamp"])

    for verdict in verdicts:
        same_flow = (
            packet["source_ip"] == verdict["source_ip"]
            and packet["destination_ip"] == verdict["destination_ip"]
            and packet["protocol"] == verdict["protocol"]
            and packet["source_port"] == verdict["source_port"]
            and packet["destination_port"] == verdict["destination_port"]
        )

        if not same_flow:
            continue

        verdict_time = datetime.fromisoformat(verdict["timestamp"])
        if abs((packet_time - verdict_time).total_seconds()) <= 5:
            packet["action"] = verdict["action"]
            packet["verdict_source"] = "nftables_kernel_log"
            break

with OUTPUT.open("w", encoding="utf-8") as f:
    for packet in packets:
        f.write(json.dumps(packet) + "\n")

accepted = sum(p["action"] == "ACCEPT" for p in packets)
rejected = sum(p["action"] == "REJECT" for p in packets)
pending = sum(p["action"] == "PENDING_VERDICT" for p in packets)

print(f"Packets processed: {len(packets)}")
print(f"ACCEPT: {accepted}")
print(f"REJECT: {rejected}")
print(f"PENDING_VERDICT: {pending}")
print(f"Saved to {OUTPUT}")
