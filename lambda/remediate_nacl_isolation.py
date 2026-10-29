#!/usr/bin/env python3

"""
NACL Threat Isolation Remediation Function

Receives a Suricata alert, validates its IP address and severity,
checks protected IPs and remediation policy, and optionally creates
a DENY rule in a dedicated AWS Network ACL.

Dry-run is the default. Automatic containment must be explicitly
enabled in the policy before a NACL can be modified.
"""

import ipaddress
import json
import logging
import os
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------
# 1. CONFIGURATION
# ---------------------------------------------------------

MODULE_DIR = Path(__file__).resolve().parent

BASE_DIR = (
    MODULE_DIR
    if (MODULE_DIR / "policies").is_dir()
    else MODULE_DIR.parent
)

POLICY_FILE = BASE_DIR / "policies" / "remediation_policy.json"
PROTECTED_IPS_FILE = BASE_DIR / "policies" / "protected_ips.json"

DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
DEFAULT_NACL_ID = os.getenv(
    "NETWORK_ACL_ID",
    "acl-72df68091d459c0d1"
)

DEFAULT_ENDPOINT = os.getenv(
    "AWS_ENDPOINT_URL",
    "http://localhost:4566"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# 2. LOAD SECURITY POLICIES
# ---------------------------------------------------------

def load_json_file(file_path):
    """Load a JSON configuration file."""

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_security_configuration():
    """Load remediation policy and protected IP addresses."""

    policy = load_json_file(POLICY_FILE)
    protected_ips = load_json_file(PROTECTED_IPS_FILE)

    return policy, protected_ips


# ---------------------------------------------------------
# 3. VALIDATE IP ADDRESSES
# ---------------------------------------------------------

def validate_ip_address(ip_value):
    """Validate and normalize an IPv4 or IPv6 address."""

    if not isinstance(ip_value, str):
        raise ValueError("IP address must be a string.")

    try:
        return ipaddress.ip_address(ip_value.strip())

    except ValueError:
        raise ValueError(
            f"Invalid IP address rejected: {ip_value}"
        )


# ---------------------------------------------------------
# 4. CHECK PROTECTED IP ADDRESSES
# ---------------------------------------------------------

def is_protected_ip(ip_address, protected_configuration):
    """Check whether an IP is on the protected list."""

    if ip_address.version == 4:
        protected_list = protected_configuration.get(
            "protected_ipv4", []
        )
    else:
        protected_list = protected_configuration.get(
            "protected_ipv6", []
        )

    normalized_protected = set()

    for protected_value in protected_list:
        normalized_protected.add(
            str(validate_ip_address(protected_value))
        )

    return str(ip_address) in normalized_protected


# ---------------------------------------------------------
# 5. CHECK REMEDIATION ELIGIBILITY
# ---------------------------------------------------------

def check_alert_eligibility(alert, policy, protected_ips):
    """Determine whether an alert qualifies for containment."""

    if not isinstance(alert, dict):
        raise ValueError("Alert must be a JSON object.")

    direction = alert.get("direction", "inbound")

    if direction not in ("inbound", "outbound"):
        raise ValueError(
            "Direction must be either inbound or outbound."
        )

    if direction == "inbound":
        ip_value = alert.get("source_ip")
    else:
        ip_value = alert.get("destination_ip")

    target_ip = validate_ip_address(ip_value)

    severity = alert.get("severity")

    try:
        severity = int(severity)
    except (TypeError, ValueError):
        raise ValueError("Alert severity must be an integer.")

    if severity not in (1, 2, 3):
        raise ValueError("Unsupported alert severity.")

    if is_protected_ip(target_ip, protected_ips):
        raise ValueError(
            f"Protected IP cannot be blocked: {target_ip}"
        )

    severity_actions = policy.get("severity_actions", {})
    action = severity_actions.get(str(severity))

    if action != "eligible_for_containment":
        raise ValueError(
            f"Severity {severity} is not eligible for containment."
        )

    threshold = policy.get(
        "containment_severity_threshold", 1
    )

    if severity > threshold:
        raise ValueError(
            "Alert severity does not meet containment threshold."
        )

    return target_ip, direction, severity


# ---------------------------------------------------------
# 6. CREATE EC2 CLIENT
# ---------------------------------------------------------

def create_ec2_client():
    """Create an EC2 client for AWS or LocalStack."""

    return boto3.client(
        "ec2",
        endpoint_url=DEFAULT_ENDPOINT,
        region_name=DEFAULT_REGION
    )


# ---------------------------------------------------------
# 7. CHECK EXISTING NACL RULES
# ---------------------------------------------------------

def find_available_rule_number(
    ec2_client,
    nacl_id,
    policy,
    egress=False
):
    """
    Find an unused rule number within the approved policy range.

    Lower NACL rule numbers have higher priority.
    """

    response = ec2_client.describe_network_acls(
        NetworkAclIds=[nacl_id]
    )

    network_acls = response.get("NetworkAcls", [])

    if len(network_acls) != 1:
        raise ValueError("Expected exactly one Network ACL.")

    nacl = network_acls[0]

    if nacl.get("IsDefault"):
        raise ValueError(
            "Refusing to modify a default Network ACL."
        )

    entries = nacl.get("Entries", [])

    used_numbers = {
        entry["RuleNumber"]
        for entry in entries
        if entry.get("Egress", False) == egress
    }

    limits = policy.get("containment_limits", {})

    minimum = int(limits.get("minimum_nacl_rule_number", 100))
    maximum = int(limits.get("maximum_nacl_rule_number", 199))

    for rule_number in range(minimum, maximum + 1):

        if rule_number not in used_numbers:
            return rule_number

    raise ValueError(
        "No available NACL rule number in approved range."
    )


# ---------------------------------------------------------
# 8. CREATE DENY RULE
# ---------------------------------------------------------

def create_deny_rule(
    ec2_client,
    nacl_id,
    malicious_ip,
    policy,
    direction="inbound"
):
    """Insert a safe inbound or outbound DENY rule."""

    expected_nacl_id = DEFAULT_NACL_ID

    if nacl_id != expected_nacl_id:
        raise ValueError(
            "Refusing to modify an NACL other than the approved test NACL."
        )

    if direction not in ("inbound", "outbound"):
        raise ValueError(
            "Direction must be either inbound or outbound."
        )

    egress = direction == "outbound"

    limits = policy.get("containment_limits", {})

    max_rules = int(
        limits.get("maximum_block_rules_per_execution", 1)
    )

    if max_rules != 1:
        raise ValueError(
            "This function permits exactly one block rule per execution."
        )

    if malicious_ip.version == 4:
        cidr_parameter = {
            "CidrBlock": f"{malicious_ip}/32"
        }
    else:
        cidr_parameter = {
            "Ipv6CidrBlock": f"{malicious_ip}/128"
        }

    response = ec2_client.describe_network_acls(
        NetworkAclIds=[nacl_id]
    )

    network_acls = response.get("NetworkAcls", [])

    if len(network_acls) != 1:
        raise ValueError("Expected exactly one Network ACL.")

    nacl = network_acls[0]

    if nacl.get("IsDefault"):
        raise ValueError(
            "Refusing to modify a default Network ACL."
        )

    associations = nacl.get("Associations", [])

    expected_subnet_id = "subnet-f4aed758b33e3cf34"

    if not any(
        association.get("SubnetId") == expected_subnet_id
        for association in associations
    ):
        raise ValueError(
            "The approved test subnet is not associated with this NACL."
        )

    entries = nacl.get("Entries", [])

    # Reject an existing exact-IP DENY rule in the requested direction.
    for entry in entries:

        if malicious_ip.version == 4:
            same_ip = (
                entry.get("CidrBlock")
                == cidr_parameter.get("CidrBlock")
            )
        else:
            same_ip = (
                entry.get("Ipv6CidrBlock")
                == cidr_parameter.get("Ipv6CidrBlock")
            )

        is_deny_rule = entry.get("RuleAction") == "deny"

        if (
            same_ip
            and entry.get("Egress") is egress
            and is_deny_rule
        ):
            raise ValueError(
                f"A {direction} DENY rule already exists for this IP address."
            )

    rule_number = find_available_rule_number(
        ec2_client,
        nacl_id,
        policy,
        egress=egress
    )

    request = {
        "NetworkAclId": nacl_id,
        "RuleNumber": rule_number,
        "Protocol": "-1",
        "RuleAction": "deny",
        "Egress": egress,
        **cidr_parameter
    }

    ec2_client.create_network_acl_entry(**request)

    return {
        "network_acl_id": nacl_id,
        "subnet_id": expected_subnet_id,
        "rule_number": rule_number,
        "direction": direction,
        "action": "deny",
        "blocked_ip": str(malicious_ip),
        "protocol": "all"
    }



# ---------------------------------------------------------
# 9. MAIN LAMBDA HANDLER
# ---------------------------------------------------------

def lambda_handler(event, context=None):
    """
    Lambda entry point.

    Expected event example:

    {
        "source_ip": "198.51.100.25",
        "severity": 1,
        "signature": "Test malicious activity",
        "signature_id": 9999999
    }    """

    try:

        policy, protected_ips = load_security_configuration()

        # Support both direct Lambda events and EventBridge envelopes.
        if isinstance(event, dict) and "detail" in event:
            if (
                event.get("source") != "cloud-network-nids.suricata"
                or event.get("detail-type") != "Suricata High Severity Alert"
                or not isinstance(event.get("detail"), dict)
            ):
                raise ValueError("Unrecognized or invalid EventBridge event.")

            event = event["detail"]

        target_ip, direction, severity = check_alert_eligibility(
    event,
    policy,
    protected_ips
)

        automatic_enabled = policy.get(
            "automatic_containment_enabled", False
        )

        # Safe default: do not change the NACL.
        if not automatic_enabled:

            return {
                "statusCode": 200,
                "status": "DRY_RUN",
                "message": (
                    "Alert passed validation, but automatic "
                    "containment is disabled."
                ),
                "target_ip": str(target_ip),
                "direction": direction,
                "severity": severity,
                "containment_requested": False,
                "nacl_modified": False
            }

        # Enforcement only occurs when explicitly enabled.
        ec2_client = create_ec2_client()

        result = create_deny_rule(
            ec2_client,
            DEFAULT_NACL_ID,
            target_ip,
            policy,
            direction=direction
        )

        logger.warning(
            "NACL DENY rule created: %s",
            json.dumps(result)
        )

        return {
            "statusCode": 200,
            "status": "CONTAINMENT_APPLIED",
            "message": f"{direction.capitalize()} DENY rule successfully created.",
            "containment_requested": True,
            "nacl_modified": True,
            "result": result
        }

    except (ValueError, FileNotFoundError, KeyError) as error:

        logger.warning("Remediation rejected: %s", error)

        return {
            "statusCode": 400,
            "status": "REJECTED",
            "message": str(error),
            "containment_requested": False,
            "nacl_modified": False
        }

    except ClientError as error:

        logger.exception("AWS/LocalStack API error")

        return {
            "statusCode": 500,
            "status": "API_ERROR",
            "message": str(error),
            "containment_requested": False,
            "nacl_modified": False
        }

    except Exception as error:

        logger.exception("Unexpected remediation error")

        return {
            "statusCode": 500,
            "status": "INTERNAL_ERROR",
            "message": str(error),
            "containment_requested": False,
            "nacl_modified": False
        }


# ---------------------------------------------------------
# 10. LOCAL TESTING
# ---------------------------------------------------------

if __name__ == "__main__":

    test_event = {
        "source_ip": "198.51.100.25",
        "severity": 1,
        "signature": "CONTROLLED TEST ALERT",
        "signature_id": 9999999
    }

    result = lambda_handler(test_event)

    print(json.dumps(result, indent=2))
