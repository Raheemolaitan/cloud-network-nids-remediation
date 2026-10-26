#!/usr/bin/env python3

"""
Suricata Flow and Alert Parser

Reads Suricata EVE JSON records, extracts security alerts,
validates IP addresses, and classifies alerts for review.

This parser does NOT block traffic.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


DEFAULT_EVE_LOG = "/var/log/suricata/eve.json"

# Alerts at these severity levels are flagged for review.
REVIEW_SEVERITIES = {1, 2}

# Protected networks used to classify traffic direction.
HOME_NET = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def classify_direction(source_ip, destination_ip):
    """Classify traffic relative to the protected HOME_NET."""

    source = ipaddress.ip_address(source_ip)
    destination = ipaddress.ip_address(destination_ip)

    source_internal = any(
        source.version == network.version and source in network
        for network in HOME_NET
    )

    destination_internal = any(
        destination.version == network.version and destination in network
        for network in HOME_NET
    )

    if source_internal and not destination_internal:
        return "outbound"

    if destination_internal and not source_internal:
        return "inbound"

    return "internal"


def validate_ip(value):
    """Validate an IPv4 or IPv6 address."""
    if not isinstance(value, str):
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_alert(event):
    """Extract and validate useful information from an alert."""

    alert = event.get("alert")

    if not isinstance(alert, dict):
        return None

    source_ip = validate_ip(event.get("src_ip"))
    destination_ip = validate_ip(event.get("dest_ip"))

    # Do not process alerts with invalid or missing IP addresses.
    if source_ip is None or destination_ip is None:
        return None

    severity = alert.get("severity")

    try:
        severity = int(severity)
    except (TypeError, ValueError):
        severity = None

    return {
        "timestamp": event.get("timestamp"),
        "source_ip": source_ip,
        "source_port": event.get("src_port"),
        "destination_ip": destination_ip,
        "destination_port": event.get("dest_port"),
        "direction": classify_direction(source_ip, destination_ip),
        "protocol": event.get("proto"),
        "interface": event.get("in_iface"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": severity,
        "action": alert.get("action"),
        "requires_review": severity in REVIEW_SEVERITIES,
        "containment_requested": False
    }


def process_log(log_path):
    """Read EVE JSON records and extract valid alert events."""

    results = []
    total_records = 0
    alert_records = 0
    skipped_records = 0

    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"EVE log not found: {path}")

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

            if event.get("event_type") != "alert":
                continue

            alert_records += 1

            parsed = parse_alert(event)

            if parsed is None:
                skipped_records += 1
                continue

            results.append(parsed)

    summary = {
        "log_file": str(path),
        "total_records": total_records,
        "alert_records": alert_records,
        "valid_alerts": len(results),
        "skipped_records": skipped_records,
        "review_alerts": sum(
            item["requires_review"] for item in results
        ),
        "containment_requested": False,
        "processed_at": datetime.now(timezone.utc).isoformat()
    }

    return summary, results


def main():

    argument_parser = argparse.ArgumentParser(
        description="Parse Suricata EVE JSON alerts."
    )

    argument_parser.add_argument(
        "--input",
        default=DEFAULT_EVE_LOG,
        help="Path to Suricata eve.json"
    )

    argument_parser.add_argument(
        "--output",
        help="Optional path to save parsed alert JSON"
    )

    args = argument_parser.parse_args()

    try:
        summary, alerts = process_log(args.input)

    except (FileNotFoundError, PermissionError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    output = {
        "summary": summary,
        "alerts": alerts
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

        print(f"Parsed results saved to: {output_path}")

    else:
        print(rendered_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
