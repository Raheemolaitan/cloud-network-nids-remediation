#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "lambda"))

from remediate_nacl_isolation import (
    validate_ip_address,
    check_alert_eligibility,
    lambda_handler
)


POLICY = {
    "automatic_containment_enabled": False,
    "containment_severity_threshold": 1,
    "severity_actions": {
        "1": "eligible_for_containment",
        "2": "investigation_required",
        "3": "log_only"
    }
}

PROTECTED_IPS = {
    "protected_ipv4": ["10.0.3.15", "10.0.3.20"],
    "protected_ipv6": []
}


class TestRemediationUnit(unittest.TestCase):

    def test_valid_ip(self):
        result = validate_ip_address("198.51.100.25")
        self.assertEqual(str(result), "198.51.100.25")

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            validate_ip_address("999.999.999.999")

    def test_protected_ip_rejected(self):
        alert = {
            "source_ip": "10.0.3.15",
            "severity": 1,
            "direction": "inbound"
        }

        with self.assertRaises(ValueError):
            check_alert_eligibility(
                alert, POLICY, PROTECTED_IPS
            )

    def test_severity_two_rejected(self):
        alert = {
            "source_ip": "198.51.100.25",
            "severity": 2,
            "direction": "inbound"
        }

        with self.assertRaises(ValueError):
            check_alert_eligibility(
                alert, POLICY, PROTECTED_IPS
            )

    def test_invalid_direction_rejected(self):
        alert = {
            "source_ip": "198.51.100.25",
            "severity": 1,
            "direction": "sideways"
        }

        with self.assertRaises(ValueError):
            check_alert_eligibility(
                alert, POLICY, PROTECTED_IPS
            )

    @patch(
        "remediate_nacl_isolation.load_security_configuration",
        return_value=(POLICY, PROTECTED_IPS)
    )
    def test_valid_alert_stays_in_dry_run(self, mock_config):
        alert = {
            "source_ip": "198.51.100.25",
            "severity": 1,
            "direction": "inbound"
        }

        result = lambda_handler(alert)

        self.assertEqual(result["status"], "DRY_RUN")
        self.assertFalse(result["nacl_modified"])
        self.assertFalse(result["containment_requested"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNACLContainmentSafety(unittest.TestCase):

    def setUp(self):
        from remediate_nacl_isolation import (
            create_deny_rule,
            DEFAULT_NACL_ID
        )

        self.create_deny_rule = create_deny_rule
        self.nacl_id = DEFAULT_NACL_ID

        self.policy = {
            "containment_limits": {
                "maximum_block_rules_per_execution": 1,
                "minimum_nacl_rule_number": 100,
                "maximum_nacl_rule_number": 199
            }
        }

        self.base_nacl = {
            "NetworkAclId": self.nacl_id,
            "IsDefault": False,
            "Associations": [
                {
                    "SubnetId": "subnet-f4aed758b33e3cf34"
                }
            ],
            "Entries": [
                {
                    "RuleNumber": 200,
                    "Egress": False,
                    "RuleAction": "allow",
                    "CidrBlock": "0.0.0.0/0"
                }
            ]
        }

    def make_client(self, nacl):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.describe_network_acls.return_value = {
            "NetworkAcls": [nacl]
        }
        return client

    def test_default_nacl_rejected(self):
        nacl = dict(self.base_nacl)
        nacl["IsDefault"] = True
        client = self.make_client(nacl)

        with self.assertRaises(ValueError):
            self.create_deny_rule(
                client,
                self.nacl_id,
                validate_ip_address("198.51.100.25"),
                self.policy
            )

        client.create_network_acl_entry.assert_not_called()

    def test_wrong_subnet_rejected(self):
        nacl = dict(self.base_nacl)
        nacl["Associations"] = [
            {"SubnetId": "subnet-not-approved"}
        ]
        client = self.make_client(nacl)

        with self.assertRaises(ValueError):
            self.create_deny_rule(
                client,
                self.nacl_id,
                validate_ip_address("198.51.100.25"),
                self.policy
            )

        client.create_network_acl_entry.assert_not_called()

    def test_existing_deny_rule_rejected(self):
        nacl = dict(self.base_nacl)
        nacl["Entries"].append({
            "RuleNumber": 101,
            "Egress": False,
            "RuleAction": "deny",
            "CidrBlock": "198.51.100.25/32"
        })
        client = self.make_client(nacl)

        with self.assertRaises(ValueError):
            self.create_deny_rule(
                client,
                self.nacl_id,
                validate_ip_address("198.51.100.25"),
                self.policy
            )

        client.create_network_acl_entry.assert_not_called()

    def test_existing_allow_rule_does_not_block_creation(self):
        nacl = dict(self.base_nacl)
        nacl["Entries"].append({
            "RuleNumber": 200,
            "Egress": False,
            "RuleAction": "allow",
            "CidrBlock": "198.51.100.25/32"
        })
        client = self.make_client(nacl)

        result = self.create_deny_rule(
            client,
            self.nacl_id,
            validate_ip_address("198.51.100.25"),
            self.policy
        )

        self.assertEqual(result["rule_number"], 100)
        client.create_network_acl_entry.assert_called_once()

    def test_first_available_rule_number_selected(self):
        nacl = dict(self.base_nacl)
        nacl["Entries"] = [
            {
                "RuleNumber": number,
                "Egress": False,
                "RuleAction": "deny",
                "CidrBlock": f"198.51.100.{number}/32"
            }
            for number in (100, 101, 102, 200)
        ]
        client = self.make_client(nacl)

        result = self.create_deny_rule(
            client,
            self.nacl_id,
            validate_ip_address("198.51.100.25"),
            self.policy
        )

        self.assertEqual(result["rule_number"], 103)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAdditionalContainmentCases(unittest.TestCase):

    def setUp(self):
        from remediate_nacl_isolation import (
            create_deny_rule,
            DEFAULT_NACL_ID
        )

        self.create_deny_rule = create_deny_rule
        self.nacl_id = DEFAULT_NACL_ID

        self.policy = {
            "containment_limits": {
                "maximum_block_rules_per_execution": 1,
                "minimum_nacl_rule_number": 100,
                "maximum_nacl_rule_number": 199
            }
        }

    def make_client(self, nacl):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.describe_network_acls.return_value = {
            "NetworkAcls": [nacl]
        }
        return client

    def test_exhausted_rule_range_rejected(self):
        nacl = {
            "IsDefault": False,
            "Associations": [
                {"SubnetId": "subnet-f4aed758b33e3cf34"}
            ],
            "Entries": [
                {
                    "RuleNumber": number,
                    "Egress": False,
                    "RuleAction": "deny",
                    "CidrBlock": f"192.0.2.{number % 255}/32"
                }
                for number in range(100, 200)
            ]
        }

        client = self.make_client(nacl)

        with self.assertRaises(ValueError):
            self.create_deny_rule(
                client,
                self.nacl_id,
                validate_ip_address("198.51.100.25"),
                self.policy
            )

        client.create_network_acl_entry.assert_not_called()

    def test_outbound_deny_rule_uses_egress(self):
        nacl = {
            "IsDefault": False,
            "Associations": [
                {"SubnetId": "subnet-f4aed758b33e3cf34"}
            ],
            "Entries": []
        }

        client = self.make_client(nacl)

        result = self.create_deny_rule(
            client,
            self.nacl_id,
            validate_ip_address("198.51.100.25"),
            self.policy,
            direction="outbound"
        )

        self.assertEqual(result["direction"], "outbound")
        self.assertEqual(result["rule_number"], 100)

        request = client.create_network_acl_entry.call_args.kwargs

        self.assertTrue(request["Egress"])
        self.assertEqual(
            request["CidrBlock"],
            "198.51.100.25/32"
        )
        self.assertEqual(request["RuleAction"], "deny")


if __name__ == "__main__":
    unittest.main(verbosity=2)
