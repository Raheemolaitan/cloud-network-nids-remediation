#!/usr/bin/env python3
"""Safely publish eligible Suricata alerts to Amazon EventBridge."""

import argparse
import ipaddress
import json
import logging
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "logs" / "parsed_alerts.json"

# EventBridge PutEvents accepts a maximum of 10 entries per request.
MAX_EVENTS_PER_PUT = 10

DEFAULT_ENDPOINT = "http://localhost:4566"
DEFAULT_REGION = "us-east-1"
DEFAULT_EVENT_BUS = "default"

EVENT_SOURCE = "cloud-network-nids.suricata"
EVENT_DETAIL_TYPE = "Suricata High Severity Alert"

ALLOWED_DIRECTIONS = {"inbound", "outbound"}
MAX_EVENT_DETAIL_BYTES = 250 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


def valid_ip(value):
    """Return True only when value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def load_alerts(input_file):
    """Load the existing parser output without modifying it."""
    with input_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict) or not isinstance(data.get("alerts"), list):
        raise ValueError("Input must contain an alerts list.")

    return data["alerts"]


def select_eligible_alerts(alerts):
    """Select severity-1 alerts suitable for inbound/outbound routing."""
    eligible = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        if alert.get("severity") != 1:
            continue

        if alert.get("direction") not in ALLOWED_DIRECTIONS:
            continue

        if alert.get("containment_requested") is not False:
            continue

        if not valid_ip(alert.get("source_ip")):
            continue

        if not valid_ip(alert.get("destination_ip")):
            continue

        if not isinstance(alert.get("signature_id"), int):
            continue

        if not isinstance(alert.get("signature"), str):
            continue

        eligible.append(alert)

    return eligible


def build_event_entry(alert, event_bus):
    """Convert one parsed alert into an EventBridge entry."""
    detail = {
        "timestamp": alert.get("timestamp"),
        "source_ip": alert["source_ip"],
        "source_port": alert.get("source_port"),
        "destination_ip": alert["destination_ip"],
        "destination_port": alert.get("destination_port"),
        "direction": alert["direction"],
        "protocol": alert.get("protocol"),
        "interface": alert.get("interface"),
        "severity": alert["severity"],
        "signature_id": alert["signature_id"],
        "signature": alert["signature"],
        "category": alert.get("category"),
        "action": alert.get("action"),
        "containment_requested": False
    }

    detail_json = json.dumps(detail, separators=(",", ":"))

    if len(detail_json.encode("utf-8")) > MAX_EVENT_DETAIL_BYTES:
        raise ValueError("Event detail exceeds EventBridge size limit.")

    return {
        "Source": EVENT_SOURCE,
        "DetailType": EVENT_DETAIL_TYPE,
        "Detail": detail_json,
        "EventBusName": event_bus
    }


def publish_events(entries, endpoint, region):
    """Send prepared events to EventBridge."""
    client = boto3.client(
        "events",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

    response = client.put_events(Entries=entries)

    failed = response.get("FailedEntryCount", 0)

    for index, result in enumerate(response.get("Entries", [])):
        if result.get("EventId"):
            logger.info(
                "Published event %d with ID %s",
                index + 1,
                result["EventId"]
            )
        else:
            logger.error(
                "Event %d failed: %s",
                index + 1,
                result.get("ErrorMessage", "Unknown EventBridge error")
            )

    return failed


def main():
    parser = argparse.ArgumentParser(
        description="Publish eligible Suricata alerts to EventBridge."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Path to the parsed Suricata alerts JSON file."
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Maximum number of alerts to process. Default: 1."
    )

    parser.add_argument(
        "--publish",
        action="store_true",
        help="Actually publish events. Without this option, run in dry-run mode."
    )

    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="EventBridge endpoint. Default: LocalStack."
    )

    parser.add_argument(
        "--region",
        default=DEFAULT_REGION,
        help="AWS region."
    )

    parser.add_argument(
        "--event-bus",
        default=DEFAULT_EVENT_BUS,
        help="EventBridge event bus."
    )

    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1.")

    if args.limit > MAX_EVENTS_PER_PUT:
        parser.error(
            f"--limit cannot exceed {MAX_EVENTS_PER_PUT} "
            "because EventBridge PutEvents accepts at most 10 entries per request."
        )

    if not args.input.is_file():
        parser.error(
            f"Input file does not exist: {args.input}. "
            "Generate it first with: "
            "python3 parser/suricata_flow_parser.py "
            "--input /var/log/suricata/eve.json "
            "--output logs/parsed_alerts.json"
        )

    try:
        alerts = load_alerts(args.input)
        eligible = select_eligible_alerts(alerts)
        selected = eligible[:args.limit]

        logger.info("Total parsed alerts: %d", len(alerts))
        logger.info("Eligible severity-1 alerts: %d", len(eligible))
        logger.info("Selected for this run: %d", len(selected))

        if not selected:
            logger.info("No eligible alerts found.")
            return 0

        entries = [
            build_event_entry(alert, args.event_bus)
            for alert in selected
        ]

        if not args.publish:
            logger.info("DRY RUN: no events were published.")
            for index, alert in enumerate(selected, start=1):
                logger.info(
                    "Event %d: %s -> %s | Direction: %s | SID: %s",
                    index,
                    alert["source_ip"],
                    alert["destination_ip"],
                    alert["direction"],
                    alert["signature_id"]
                )
            return 0

        failed = publish_events(entries, args.endpoint, args.region)

        if failed:
            logger.error("%d event(s) failed to publish.", failed)
            return 1

        logger.info("All selected events were accepted by EventBridge.")
        return 0

    except (ValueError, OSError, json.JSONDecodeError) as exc:
        logger.error("Input or validation error: %s", exc)
        return 1
    except (BotoCoreError, ClientError) as exc:
        logger.error("AWS/EventBridge error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
