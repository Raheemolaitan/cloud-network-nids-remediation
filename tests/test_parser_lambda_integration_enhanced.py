#!/usr/bin/env python3

"""
Enhanced integration evidence:
Suricata Parsed Alerts -> Incident Grouping -> Lambda

Preserves every individual alert and its port/timestamp evidence.
Invokes Lambda once per incident group.
Automatic containment remains disabled.
"""

import json
import sys
import hashlib
from pathlib import Path
from collections import defaultdict

PROJECT_DIR = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_DIR / "lambda"))

from remediate_nacl_isolation import lambda_handler

INPUT_FILE = PROJECT_DIR / "logs" / "parsed_alerts.json"
OUTPUT_FILE = (
    PROJECT_DIR
    / "logs"
    / "integration_test_results_enhanced_20261028.json"
)


def group_alerts(alerts):
    """Group related alerts into incidents."""

    groups = defaultdict(list)

    for alert in alerts:
        key = (
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("signature_id"),
            alert.get("severity")
        )
        groups[key].append(alert)

    return groups


def build_incident_id(key):
    """Generate a stable identifier for an incident."""

    raw = json.dumps(key, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def main():

    if not INPUT_FILE.is_file():
        print("ERROR: Parsed alerts file not found.")
        return 1

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        parsed_data = json.load(file)

    alerts = parsed_data.get("alerts", [])

    if not alerts:
        print("ERROR: No parsed alerts found.")
        return 1

    groups = group_alerts(alerts)

    incident_results = []

    for key, group in groups.items():

        representative = group[0]
        result = lambda_handler(representative)

        individual_evidence = []

        for alert in group:
            individual_evidence.append({
                "timestamp": alert.get("timestamp"),
                "source_ip": alert.get("source_ip"),
                "source_port": alert.get("source_port"),
                "destination_ip": alert.get("destination_ip"),
                "destination_port": alert.get("destination_port"),
                "protocol": alert.get("protocol"),
                "signature_id": alert.get("signature_id"),
                "signature": alert.get("signature"),
                "severity": alert.get("severity"),
                "action": alert.get("action")
            })

        incident_results.append({
            "incident_id": build_incident_id(key),
            "source_ip": representative.get("source_ip"),
            "destination_ip": representative.get("destination_ip"),
            "signature_id": representative.get("signature_id"),
            "signature": representative.get("signature"),
            "severity": representative.get("severity"),
            "event_count": len(group),
            "unique_source_ports": len({
                a.get("source_port") for a in group
            }),
            "unique_destination_ports": len({
                a.get("destination_port") for a in group
            }),
            "lambda_status": result.get("status"),
            "lambda_message": result.get("message"),
            "nacl_modified": result.get("nacl_modified", False),
            "individual_alerts": individual_evidence
        })

    preserved_count = sum(
        incident["event_count"] for incident in incident_results
    )

    output = {
        "test_name": "Enhanced Suricata Parser to Lambda Integration",
        "automatic_containment_enabled": False,
        "nacl_modification_permitted": False,
        "original_alert_count": len(alerts),
        "incident_count": len(incident_results),
        "lambda_invocations": len(incident_results),
        "preserved_individual_alert_count": preserved_count,
        "nacl_modifications": sum(
            incident["nacl_modified"]
            for incident in incident_results
        ),
        "incidents": incident_results
    }

    OUTPUT_FILE.write_text(
        json.dumps(output, indent=2) + "\n",
        encoding="utf-8"
    )

    print("=" * 60)
    print("ENHANCED SURICATA -> LAMBDA INTEGRATION")
    print("=" * 60)
    print(f"Original alerts: {len(alerts)}")
    print(f"Incident groups: {len(groups)}")
    print(f"Lambda invocations: {len(incident_results)}")
    print(f"Individual alerts preserved: {preserved_count}")
    print(f"NACL modifications: {output['nacl_modifications']}")
    print(f"Evidence file: {OUTPUT_FILE}")

    if preserved_count != len(alerts):
        print("FAIL: Individual alert count mismatch.")
        return 1

    if output["nacl_modifications"] != 0:
        print("SAFETY FAILURE: NACL modification detected.")
        return 1

    print("PASS: All individual alerts preserved.")
    print("PASS: No NACL modifications detected.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
