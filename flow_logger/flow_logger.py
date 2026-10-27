import time
import json
from datetime import datetime, timezone
from collections import defaultdict
from threading import Lock

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

INTERFACE = "enp0s8"


def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif IPv6 in packet:
        return "IPv6"
    elif IP in packet:
        protocol_number = packet[IP].proto
        if protocol_number == 2:
            return "IGMP"
        return str(protocol_number)
    else:
        return "OTHER"


def get_ip_addresses(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    else:
        return None, None


def get_ports(packet):
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].sport, packet[UDP].dport
    else:
        return None, None


def get_packet_size(packet):
    return len(packet)


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def build_packet_record(packet):
    source_ip, destination_ip = get_ip_addresses(packet)
    source_port, destination_port = get_ports(packet)

    return {
        "timestamp": get_timestamp(),
        "interface": INTERFACE,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": get_protocol(packet),
        "bytes": get_packet_size(packet),
        "action": "PENDING_VERDICT"
    }


OUTPUT_FILE = "logs/network_flows.jsonl"
FLOW_OUTPUT_FILE = "logs/network_flows_aggregated.jsonl"
FLOW_TIMEOUT_SECONDS = 60

flow_stats = defaultdict(lambda: {
    "packets": 0,
    "total_bytes": 0,
    "first_seen": None,
    "last_seen": None,
    "last_seen_monotonic": None
})

FLOW_LOCK = Lock()
completed_flows = []


def save_packet_record(record):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record) + "\n")

def get_flow_key(packet):
    source_ip, destination_ip = get_ip_addresses(packet)
    source_port, destination_port = get_ports(packet)
    protocol = get_protocol(packet)

    return (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )

def expire_old_flows():
    current_time = time.monotonic()

    with FLOW_LOCK:
        expired_keys = []

        for flow_key, stats in flow_stats.items():
            last_seen = stats["last_seen_monotonic"]

            if last_seen is not None:
                if current_time - last_seen >= FLOW_TIMEOUT_SECONDS:
                    expired_keys.append(flow_key)

        for flow_key in expired_keys:
            stats = flow_stats.pop(flow_key)

            completed_flows.append({
                "flow_key": flow_key,
                "stats": stats.copy()
            })

def update_flow_stats(packet):
    flow_key = get_flow_key(packet)
    packet_size = get_packet_size(packet)
    timestamp = get_timestamp()
    current_time = time.monotonic()
    expire_old_flows()

    with FLOW_LOCK:
        flow = flow_stats[flow_key]

        flow["packets"] += 1
        flow["total_bytes"] += packet_size

        if flow["first_seen"] is None:
            flow["first_seen"] = timestamp

        flow["last_seen"] = timestamp
        flow["last_seen_monotonic"] = current_time

def save_aggregated_flows():
    expire_old_flows()

    with FLOW_LOCK:
        with open(FLOW_OUTPUT_FILE, "w", encoding="utf-8") as log_file:

            for completed in completed_flows:
                flow_key = completed["flow_key"]
                stats = completed["stats"]

                record = {
                    "interface": INTERFACE,
                    "source_ip": flow_key[0],
                    "destination_ip": flow_key[1],
                    "source_port": flow_key[2],
                    "destination_port": flow_key[3],
                    "protocol": flow_key[4],
                    "packets": stats["packets"],
                    "total_bytes": stats["total_bytes"],
                    "first_seen": stats["first_seen"],
                    "last_seen": stats["last_seen"],
                    "status": "EXPIRED"
                }

                log_file.write(json.dumps(record) + "\n")

            for flow_key, stats in flow_stats.items():
                record = {
                    "interface": INTERFACE,
                    "source_ip": flow_key[0],
                    "destination_ip": flow_key[1],
                    "source_port": flow_key[2],
                    "destination_port": flow_key[3],
                    "protocol": flow_key[4],
                    "packets": stats["packets"],
                    "total_bytes": stats["total_bytes"],
                    "first_seen": stats["first_seen"],
                    "last_seen": stats["last_seen"],
                    "status": "ACTIVE"
                }

                log_file.write(json.dumps(record) + "\n")

def process_packet(packet):
    if IP not in packet and IPv6 not in packet:
        return

    record = build_packet_record(packet)
    save_packet_record(record)
    update_flow_stats(packet)

    print(json.dumps(record, indent=2))


def start_capture():
    print(f"Starting network flow capture on {INTERFACE}...")
    print("Press CTRL+C to stop.")

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\nStopping network capture...")

    finally:
        save_aggregated_flows()
        print(f"Aggregated flows saved to {FLOW_OUTPUT_FILE}")
if __name__ == "__main__":
    start_capture()
