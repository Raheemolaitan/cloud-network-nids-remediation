#!/usr/bin/env python3

"""
Controlled integration test:
Suricata Parser -> NACL Remediation Lambda

Groups equivalent alerts to reduce repeated processing.
Preserves original alert counts and evidence.

Automatic containment remains disabled.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

PROJECT_DIR = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_DIR / "lambda"))

from remediate_nacl_isolation import lambda_handler


PARSED_ALERTS_FILE = (
    PROJECT_DIR / "logs" / "parsed_alerts.json"
)


def group_alerts(alerts):
    """Group alerts with equivalent detection attributes."""

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


def main():

    if not PARSED_ALERTS_FILE.is_file():
        print("ERROR: Parsed alerts file not found.")
        return 1

    with PARSED_ALERTS_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:
        parsed_data = json.load(file)

    alerts = parsed_data.get("alerts", [])

    if not alerts:
        print("ERROR: No parsed alerts found.")
        return 1

    grouped_alerts = group_alerts(alerts)

    print("=" * 60)
    print("SURICATA PARSER -> LAMBDA INTEGRATION TEST")
    print("=" * 60)

    print(f"Original alerts: {len(alerts)}")
    print(f"Unique alert groups: {len(grouped_alerts)}")
    print("Automatic containment: DISABLED")
    print("NACL modification: NOT PERMITTED")
    print("-" * 60)

    results = []

    for index, (key, group) in enumerate(
        grouped_alerts.items(),
        start=1
    ):

        representative_alert = group[0]

        result = lambda_handler(representative_alert)

        results.append({
            "group_number": index,
            "source_ip": representative_alert.get("source_ip"),
            "destination_ip": representative_alert.get(
                "destination_ip"
            ),
            "signature_id": representative_alert.get(
                "signature_id"
            ),
            "signature": representative_alert.get("signature"),
            "severity": representative_alert.get("severity"),
            "event_count": len(group),
            "lambda_status": result.get("status"),
            "lambda_message": result.get("message"),
            "nacl_modified": result.get(
                "nacl_modified", False
            )
        })

    rejected = sum(
        item["lambda_status"] == "REJECTED"
        for item in results
    )

    dry_runs = sum(
        item["lambda_status"] == "DRY_RUN"
        for item in results
    )

    modified = sum(
        item["nacl_modified"]
        for item in results
    )

    output = {
        "test_name": "Suricata Parser to Lambda Integration",
        "automatic_containment_enabled": False,
        "original_alert_count": len(alerts),
        "unique_alert_groups": len(grouped_alerts),
        "lambda_invocations": len(results),
        "rejected_groups": rejected,
        "dry_run_groups": dry_runs,
        "nacl_modifications": modified,
        "results": results
    }

    output_file = (
        PROJECT_DIR
        / "logs"
        / "integration_test_results_run_20261028.json"
    )

    output_file.write_text(
        json.dumps(output, indent=2) + "\n",
        encoding="utf-8"
    )

    print(f"Original alerts: {len(alerts)}")
    print(f"Unique groups: {len(grouped_alerts)}")
    print(f"Lambda invocations: {len(results)}")
    print(f"Rejected groups: {rejected}")
    print(f"Dry-run groups: {dry_runs}")
    print(f"NACL modifications: {modified}")

    print("-" * 60)

    print("Integration results:")
    print(json.dumps(results, indent=2))

    print("-" * 60)
    print(f"Results saved to: {output_file}")

    if modified != 0:
        print("SAFETY FAILURE: NACL modification detected.")
        return 1

    if sum(item["event_count"] for item in results) != len(alerts):
        print("ERROR: Original alert count was not preserved.")
        return 1

    print("SAFETY CHECK PASSED: No NACL modifications.")
    print("EVIDENCE CHECK PASSED: All original alerts accounted for.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
