import json
import unittest
from unittest.mock import patch, MagicMock

from botocore.exceptions import ClientError

from scripts import publish_suricata_alerts as publisher


def make_alert(**overrides):
    alert = {
        "timestamp": "2026-10-28T21:38:20Z",
        "source_ip": "10.106.155.63",
        "source_port": 49720,
        "destination_ip": "198.51.100.77",
        "destination_port": 4444,
        "direction": "outbound",
        "protocol": "TCP",
        "interface": "enp0s3",
        "severity": 1,
        "signature_id": 1000005,
        "signature": "LOCAL SUSPICIOUS OUTBOUND TCP CONNECTION TO PORT 4444",
        "category": "A Network Trojan was detected",
        "action": "allowed",
        "containment_requested": False
    }
    alert.update(overrides)
    return alert


class TestAlertSelection(unittest.TestCase):

    def test_valid_severity_one_alert_is_selected(self):
        alerts = [make_alert()]
        result = publisher.select_eligible_alerts(alerts)
        self.assertEqual(len(result), 1)

    def test_severity_two_alert_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(severity=2)]
        )
        self.assertEqual(result, [])

    def test_severity_three_alert_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(severity=3)]
        )
        self.assertEqual(result, [])

    def test_internal_direction_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(direction="internal")]
        )
        self.assertEqual(result, [])

    def test_invalid_direction_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(direction="unknown")]
        )
        self.assertEqual(result, [])

    def test_invalid_source_ip_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(source_ip="not-an-ip")]
        )
        self.assertEqual(result, [])

    def test_invalid_destination_ip_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(destination_ip="not-an-ip")]
        )
        self.assertEqual(result, [])

    def test_alert_with_containment_requested_is_excluded(self):
        result = publisher.select_eligible_alerts(
            [make_alert(containment_requested=True)]
        )
        self.assertEqual(result, [])

    def test_non_dictionary_record_is_excluded(self):
        result = publisher.select_eligible_alerts(
            ["invalid-record", make_alert()]
        )
        self.assertEqual(len(result), 1)


class TestEventConstruction(unittest.TestCase):

    def test_event_contains_expected_source_and_detail(self):
        alert = make_alert()

        entry = publisher.build_event_entry(alert, "default")

        self.assertEqual(entry["Source"], publisher.EVENT_SOURCE)
        self.assertEqual(
            entry["DetailType"],
            publisher.EVENT_DETAIL_TYPE
        )
        self.assertEqual(entry["EventBusName"], "default")

        detail = json.loads(entry["Detail"])
        self.assertEqual(detail["source_ip"], "10.106.155.63")
        self.assertEqual(detail["destination_ip"], "198.51.100.77")
        self.assertEqual(detail["severity"], 1)
        self.assertFalse(detail["containment_requested"])

    def test_oversized_event_detail_is_rejected(self):
        alert = make_alert(signature="X" * 300000)

        with self.assertRaises(ValueError):
            publisher.build_event_entry(alert, "default")


class TestEventBridgePublishing(unittest.TestCase):

    @patch("scripts.publish_suricata_alerts.boto3.client")
    def test_successful_eventbridge_publish(self, mock_client):
        client = MagicMock()
        client.put_events.return_value = {
            "FailedEntryCount": 0,
            "Entries": [{"EventId": "test-event-123"}]
        }
        mock_client.return_value = client

        result = publisher.publish_events(
            [{"Source": publisher.EVENT_SOURCE}],
            "http://localhost:4566",
            "us-east-1"
        )

        self.assertEqual(result, 0)
        client.put_events.assert_called_once()

    @patch("scripts.publish_suricata_alerts.boto3.client")
    def test_failed_eventbridge_entry_is_reported(self, mock_client):
        client = MagicMock()
        client.put_events.return_value = {
            "FailedEntryCount": 1,
            "Entries": [{
                "ErrorCode": "InternalFailure",
                "ErrorMessage": "Simulated failure"
            }]
        }
        mock_client.return_value = client

        result = publisher.publish_events(
            [{"Source": publisher.EVENT_SOURCE}],
            "http://localhost:4566",
            "us-east-1"
        )

        self.assertEqual(result, 1)

    @patch("scripts.publish_suricata_alerts.boto3.client")
    def test_eventbridge_client_error_is_propagated(self, mock_client):
        client = MagicMock()
        client.put_events.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Simulated access denied"
                }
            },
            "PutEvents"
        )
        mock_client.return_value = client

        with self.assertRaises(ClientError):
            publisher.publish_events(
                [{"Source": publisher.EVENT_SOURCE}],
                "http://localhost:4566",
                "us-east-1"
            )


class TestCommandLineValidation(unittest.TestCase):

    def test_default_input_uses_reusable_filename(self):
        self.assertEqual(
            publisher.DEFAULT_INPUT,
            publisher.PROJECT_ROOT / "logs" / "parsed_alerts.json"
        )

    @patch("sys.argv",
           ["publish_suricata_alerts.py", "--limit", "11"])
    def test_limit_above_eventbridge_maximum_is_rejected(self):
        with self.assertRaises(SystemExit) as result:
            publisher.main()

        self.assertEqual(result.exception.code, 2)

    @patch("sys.argv",
           ["publish_suricata_alerts.py",
            "--input", "/tmp/nonexistent-suricata-alerts.json"])
    def test_missing_input_file_gives_generation_instructions(self):
        import contextlib
        import io

        error_output = io.StringIO()

        with contextlib.redirect_stderr(error_output):
            with self.assertRaises(SystemExit) as result:
                publisher.main()

        self.assertEqual(result.exception.code, 2)
        self.assertIn("parser/suricata_flow_parser.py", error_output.getvalue())
        self.assertIn("logs/parsed_alerts.json", error_output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
