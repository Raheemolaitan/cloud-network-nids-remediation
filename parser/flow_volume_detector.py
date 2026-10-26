#!/usr/bin/env python3

"""
Suricata Flow Volume Detector

Reads Suricata EVE JSON flow records and identifies
large outbound TCP transfers for security investigation.

This detector does NOT block traffic.
"""

import argparse
import ipaddress
import json
import sys

from pathlib import Path
from datetime import datetime, timezone


DEFAULT_EVE_LOG = "/var/log/suricata/eve.json"

# Starting threshold: 100 KB sent to the destination.
BYTE_THRESHOLD = 100 * 1024

# Our internal laboratory network.
HOME_NET = [ipaddress.ip_network("10.0.3.0/24"), ipaddress.ip_network("10.106.155.63/32")]


def validate_ip(value):
    """Validate an IPv4 or IPv6 address."""

    if not isinstance(value, str):
        return None

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def analyse_flow(event):
    """Analyse one Suricata flow event."""

    if event.get("event_type") != "flow":
        return None

    if event.get("proto") != "TCP":
        return None

    source_ip = validate_ip(event.get("src_ip"))
    destination_ip = validate_ip(event.get("dest_ip"))

    if source_ip is None or destination_ip is None:
        return None

    flow = event.get("flow")

    if not isinstance(flow, dict):
        return None

    try:
        bytes_sent = int(flow.get("bytes_toserver", 0))
        bytes_received = int(flow.get("bytes_toclient", 0))
    except (TypeError, ValueError):
        return None

    if bytes_sent < 0 or bytes_received < 0:
        return None

    # Only investigate traffic originating inside HOME_NET
    # and travelling to an address outside HOME_NET.
    is_outbound = (
        any(source_ip in network for network in HOME_NET)
        and not any(destination_ip in network for network in HOME_NET)
    )

    if not is_outbound:
        return None

    threshold_exceeded = bytes_sent >= BYTE_THRESHOLD

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "source_ip": str(source_ip),
        "source_port": event.get("src_port"),
        "destination_ip": str(destination_ip),
        "destination_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "byte_threshold": BYTE_THRESHOLD,
        "threshold_exceeded": threshold_exceeded,
        "classification": (
            "HIGH_VOLUME_OUTBOUND_TRANSFER"
            if threshold_exceeded
            else "NORMAL_VOLUME"
        ),
        "requires_review": threshold_exceeded,
        "containment_requested": False
    }


def process_log(log_path):

    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"EVE log not found: {path}")

    total_records = 0
    flow_records = 0
    outbound_flows = []
    seen_flow_ids = set()
    skipped_records = 0

    with path.open("r", encoding="utf-8") as log_file:

        for line_number, line in enumerate(log_file, start=1):

            if not line.strip():
                continue

            total_records += 1

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                skipped_records += 1
                print(
                    f"Warning: Invalid JSON on line {line_number}",
                    file=sys.stderr
                )
                continue

            if not isinstance(event, dict):
                skipped_records += 1
                continue

            if event.get("event_type") != "flow":
                continue

            flow_records += 1

            flow_id = event.get("flow_id")

            if flow_id is not None:
                if flow_id in seen_flow_ids:
                    continue
                seen_flow_ids.add(flow_id)

            result = analyse_flow(event)

            if result is not None:
                outbound_flows.append(result)

    flagged = sum(
        item["threshold_exceeded"]
        for item in outbound_flows
    )

    summary = {
        "log_file": str(path),
        "total_records": total_records,
        "flow_records": flow_records,
        "outbound_tcp_flows": len(outbound_flows),
        "high_volume_flows": flagged,
        "threshold_bytes": BYTE_THRESHOLD,
        "skipped_records": skipped_records,
        "containment_requested": False,
        "processed_at": datetime.now(timezone.utc).isoformat()
    }

    return summary, outbound_flows


def main():

    parser = argparse.ArgumentParser(
        description="Detect high-volume outbound TCP flows."
    )

    parser.add_argument(
        "--input",
        default=DEFAULT_EVE_LOG,
        help="Path to Suricata eve.json"
    )

    parser.add_argument(
        "--output",
        help="Optional JSON output file"
    )

    args = parser.parse_args()

    try:
        summary, flows = process_log(args.input)

    except (FileNotFoundError, PermissionError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    output = {
        "summary": summary,
        "flows": flows
    }

    rendered_output = json.dumps(output, indent=2)

    if args.output:

        output_path = Path(args.output)

        try:
            output_path.write_text(
                rendered_output + "\n",
                encoding="utf-8"
            )

        except OSError as error:
            print(f"Error writing output: {error}", file=sys.stderr)
            return 1

        print(f"Results saved to: {output_path}")

    else:
        print(rendered_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
