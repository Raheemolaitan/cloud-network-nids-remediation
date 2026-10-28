# Cloud Network Security: Suricata NIDS, VPC Flow Log-Inspired Inspection & NACL Threat Containment

Project Overview

This project implements a laboratory-based cloud network security monitoring and remediation system using Suricata, Python, AWS-compatible services through LocalStack, and Network Access Control Lists (NACLs).

The solution demonstrates how network activity can be monitored, suspicious traffic identified, security events analysed, and controlled network containment actions prepared through an AWS Lambda-compatible remediation function.

The current implementation analyses Suricata EVE JSON alerts and flow records. It does not yet ingest native AWS VPC Flow Logs. Native VPC Flow Log integration is identified as a future enhancement.

The project was developed as part of a Cloud Network Security assignment at Bincom Dev Center.

Important: This is a controlled virtual-machine and LocalStack laboratory implementation. It demonstrates detection, alert processing, remediation logic and API-level NACL configuration. It is not a fully deployed production AWS security architecture, and actual AWS packet-level enforcement has not been demonstrated.

Project Objectives

The primary objectives were to:

- Monitor network traffic using Suricata Network Intrusion Detection System (NIDS).
- Analyse Suricata EVE JSON events and flow records.
- Detect suspicious network activity, including SYN scans, ICMP floods and suspicious outbound connections.
- Identify unusually high-volume outbound TCP transfers using custom Python logic.
- Develop a Python-based alert parser.
- Implement a Lambda-compatible NACL remediation function using Boto3.
- Protect critical infrastructure IP addresses from accidental containment.
- Validate NACL rule creation through LocalStack's EC2 API.
- Measure the execution time of controlled NACL remediation operations.

Architecture and Workflow

The project uses two virtual machines for controlled network traffic generation and monitoring. LocalStack provides an AWS-compatible environment for testing event routing and NACL remediation operations.

High-level workflow

          Kali Linux VM
       Traffic Generation
                |
                v
       Ubuntu Linux VM
                |
                v
          Suricata NIDS
                |
                v
          EVE JSON Logs
                |
                v
       Python Alert Parser
                |
                v
       Security Validation
                |
                v
      Suricata Alert Publisher
                |
                v
          Amazon EventBridge
          (LocalStack)
                |
                v
       Lambda Remediation
       (EventBridge Trigger)
                |
                v
        Safety Policy Checks
                |
                v
       LocalStack EC2 API
                |
                v
       Dedicated Test NACL
    (only when explicitly enabled)
                |
                v
       Independent Verification

Main components

Component| Responsibility
Kali Linux| Controlled network scanning and traffic generation
Ubuntu Linux| Network monitoring and security processing
Suricata| Network intrusion detection and flow logging
EVE JSON| Stores structured detection and flow events
Python alert parser| Extracts and classifies security alerts
Suricata alert publisher| Selects eligible severity-1 alerts and publishes EventBridge events
Amazon EventBridge (LocalStack)| Routes matching high-severity alerts to the Lambda function
AWS Lambda-compatible function| Validates alerts, applies safety checks and supports controlled NACL remediation
Boto3| Communicates with AWS-compatible EC2 and EventBridge APIs
LocalStack| Simulates selected AWS services locally
Network ACL| Represents the subnet-level traffic filtering policy

Deployment distinction: Suricata runs natively on the Ubuntu virtual machine as a system service. LocalStack runs in Docker using Docker Compose. The EventBridge-to-Lambda invocation was tested locally; this does not establish production AWS deployment or packet-level enforcement.

Containment safety: Automatic containment remains disabled. The tested pipeline can route eligible alerts to Lambda, but the handler returns DRY_RUN while automatic containment is disabled. NACL changes require the explicitly enabled remediation path.

Technologies Used

- Ubuntu 24.04.5 LTS
- Kali Linux
- Suricata 7.0.3
- Python 3
- Boto3
- AWS Lambda-compatible handler
- AWS EC2 Network ACL API
- LocalStack 4.8.1
- Docker and Docker Compose
- Nmap
- Netcat
- Git and GitHub

Detection Capabilities

1. SYN Scan Detection

A custom Suricata rule detects repeated TCP SYN packets from the same source address.

Detection threshold:

- At least 20 SYN packets.
- Within 10 seconds.
- Tracked by source IP.

A controlled Nmap SYN scan was conducted against the Ubuntu test machine.

2. ICMP Flood Detection

A custom Suricata rule identifies repeated ICMP echo requests.

Detection threshold:

- At least 50 ICMP echo requests.
- Within 10 seconds.
- Tracked by source IP.

A controlled ping test generated 60 ICMP echo requests.

3. Suspicious Outbound Connection Detection

A custom Suricata rule monitors outbound TCP connection attempts to destination port 4444 outside the configured HOME_NET.

The rule generated alerts during a controlled connection test.

This is a suspicious-port heuristic, not proof of command-and-control communication.

4. High-Volume Outbound Transfer Detection

A custom Python script analyses Suricata EVE JSON flow records to identify unusually large outbound TCP transfers.

Configured threshold:

102,400 bytes (100 KiB).

The controlled Ubuntu-to-Kali transfer produced:

Measurement| Result
Bytes sent| 274,560
Bytes received| 4,166
Detection threshold| 102,400 bytes
High-volume flows detected| 1

The transfer was between laboratory virtual machines. It was not an actual internet data-exfiltration incident.

Alert Processing and Remediation

Python Alert Parser

"parser/suricata_flow_parser.py"

The parser:

- Reads Suricata EVE JSON alert records.
- Validates source and destination IP addresses.
- Extracts source and destination ports.
- Extracts protocol, interface and signature information.
- Records alert severity and action.
- Classifies traffic direction using configured HOME_NET networks.
- Identifies alerts requiring security review.

The parser does not independently execute containment actions.

Flow Volume Detector

"parser/flow_volume_detector.py"

The flow-volume detector:

- Reads Suricata flow records.
- Analyses TCP traffic.
- Validates source and destination addresses.
- Determines direction using configured laboratory network boundaries.
- Compares recorded byte counts against the 100 KiB threshold.
- Identifies high-volume flows for investigation.

The detector does not block traffic or automatically invoke the remediation function.

NACL Remediation Function

"lambda/remediate_nacl_isolation.py"

The Python remediation function uses Boto3 to communicate with the EC2 Network ACL API.

Its responsibilities include:

- Validating alert direction and IP addresses.
- Checking alert severity.
- Rejecting protected IP addresses.
- Checking the approved Network ACL.
- Preventing modification of the default NACL.
- Verifying the dedicated subnet association.
- Preventing duplicate rules.
- Selecting an available rule number.
- Creating an IPv4 or IPv6 DENY rule where eligible.

Automatic containment is disabled by default.

Controlled tests explicitly invoked the remediation function to validate its behaviour.

Security Safeguards

Safety was prioritised throughout the implementation.

Safeguard| Purpose
Automatic containment disabled| Prevents uncontrolled network changes
Protected IP list| Prevents blocking critical lab infrastructure
IP address validation| Rejects invalid addresses
Dedicated test NACL| Separates testing from shared/default NACLs
Default NACL protection| Prevents accidental modification of the default NACL
Subnet association validation| Ensures the approved test subnet is used
Duplicate rule prevention| Avoids repeated entries for the same destination
One-rule execution limit| Restricts the number of changes per execution
DRY_RUN mode| Allows validation without modifying the NACL

Protected addresses include the Kali test machine, Ubuntu monitoring machine and laboratory gateway.

Testing and Results

Test A: Network Reconnaissance Detection

A controlled Nmap SYN scan was executed against the Ubuntu virtual machine.

Result:

- Target host identified.
- TCP ports scanned.
- Suricata generated SYN scan alerts.
- Python processing grouped repeated alerts.
- Protected source IP validation prevented inappropriate containment.

ICMP Detection Test

A controlled test generated 60 ICMP echo requests.

Suricata generated ICMP flood alerts according to the configured detection threshold.

The alerts were recorded for analysis. No packet blocking was performed.

Test B: High-Volume Outbound Transfer

A controlled TCP transfer was performed from Ubuntu to Kali using Netcat.

The Suricata flow record exceeded the configured 100 KiB threshold.

The Python detector successfully identified one high-volume flow.

Outbound Threat Detection and NACL Remediation

A controlled outbound connection attempt to TCP port 4444 generated a Suricata alert.

The parser correctly classified the alert as outbound.

A synthetic alert was submitted to the Lambda handler, which returned DRY_RUN and selected the correct destination IP.

The remediation function was separately invoked to create an outbound DENY rule through LocalStack.

Independent API verification confirmed that the rule was created.

Remediation Latency Test

Four controlled remediation measurements were recorded.

Measurement| Execution time
Original| 156.329 ms
Repeat 1| 50.374 ms
Repeat 2| 82.038 ms
Repeat 3| 106.904 ms
Average| 98.911 ms
Median| 94.471 ms

These measurements cover the complete remediation function execution, including NACL lookup, validation and rule creation.

They are LocalStack API-level measurements, not production AWS performance benchmarks or end-to-end detection-to-containment measurements.

Detailed evidence is available in the "docs/" directory.

Project Structure

cloud-network-nids-remediation/
│
├── .github/
│   └── workflows/
│       └── python-tests.yml
│
├── deployment/
│   ├── iam/
│   │   ├── lambda-execution-policy.json
│   │   └── lambda-trust-policy.json
│   ├── lambda-package/
│   │   └── remediate_nacl_isolation.py
│   └── remediate-nacl-isolation-eventbridge.zip
│
├── docs/
│   ├── high-volume-outbound-test.md
│   ├── outbound-remediation-test.md
│   └── remediation-latency-test.md
│
├── flow_logger/
│   └── flow_logger.py
│
├── lambda/
│   └── remediate_nacl_isolation.py
│
├── parser/
│   ├── suricata_flow_parser.py
│   └── flow_volume_detector.py
│
├── policies/
│   ├── protected_ips.json
│   └── remediation_policy.json
│
├── scripts/
│   ├── publish_suricata_alerts.py
│   ├── parse_firewall_verdicts.py
│   └── correlate_firewall_verdicts.py
│
├── suricata/
│   └── local.rules
│
├── terraform/
│   ├── modules/
│   │   ├── network/
│   │   └── nacl/
│   ├── main.tf
│   ├── providers.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── versions.tf
│
├── tests/
│   ├── synthetic_external_flow.json
│   ├── test_parser_lambda_integration.py
│   ├── test_parser_lambda_integration_enhanced.py
│   ├── test_parser_lambda_integration_run.py
│   ├── test_remediation_unit.py
│   └── test_suricata_publisher.py
│
├── docker-compose.yml
├── .gitignore
└── README.md

Runtime logs, Terraform state, local backups, environment-specific configuration and generated test data are excluded from the published repository where appropriate.

Installation and Laboratory Setup

Prerequisites

- Ubuntu Linux virtual machine.
- Python 3.
- Git.
- Docker and Docker Compose.
- Suricata.
- LocalStack.
- Boto3.
- A separate Kali Linux virtual machine or another controlled traffic-generation environment.

1. Clone the repository

```bash

git clone https://github.com/Raheemolaitan/cloud-network-nids-remediation.git

cd cloud-network-nids-remediation

```

2. Create a Python virtual environment

```bash

python3 -m venv .venv

source .venv/bin/activate

```

3. Install Python dependencies

Install Boto3:

```bash

pip install boto3

```

4. Start LocalStack

```bash

docker compose up -d

Check the container:

docker ps

```

5. Configure LocalStack credentials

For a local test environment, configure the AWS CLI with dummy credentials and the LocalStack endpoint.

```bash

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

```

These credentials are for local simulation only. Do not use them as real AWS credentials.

6. Configure Suricata

Install Suricata on Ubuntu and configure it to monitor the intended laboratory interfaces.

Review the local rules and HOME_NET configuration before starting detection.

Validate the configuration:

```bash

sudo suricata -T -c /etc/suricata/suricata.yaml

```

Check the service:

```bash

sudo systemctl status suricata

```

Important: Interface names, IP addresses, subnet IDs, NACL IDs and policy configuration must be adjusted to match the user's own laboratory environment. The repository's test configuration is not a universal deployment template.

Important Technical Limitations

This project intentionally distinguishes laboratory validation from production cloud enforcement.

1. Flow Logs and packet inspection: Flow records provide traffic metadata, not full packet payloads. They may also be delayed. Suricata provides the direct network detection capability in this laboratory.

2. LocalStack simulation: LocalStack validates AWS-compatible API operations. Successful NACL API calls do not prove real AWS packet filtering.

3. Event-driven integration: The Suricata alert publisher, LocalStack EventBridge rule and Lambda target were integrated and tested locally. EventBridge accepted qualifying alerts and invoked the Lambda function. This validates the local event-routing workflow, not a production AWS deployment.

4. Automatic containment: Automatic containment remains disabled. No uncontrolled live remediation was performed.

5. Flow deduplication: The flow-volume detector uses flow IDs to avoid duplicate processing. Its current first-record deduplication approach may ignore later records containing higher cumulative byte counts.

6. Network direction: Outbound classification depends on configured HOME_NET and laboratory network boundaries. These settings must be aligned with the actual deployment.

7. Detection heuristics: Suspicious ports, SYN thresholds, ICMP thresholds and high-volume transfer thresholds are indicators for investigation, not automatic proof of malicious activity.

8. Production readiness: Real AWS validation would require deployed networking, IAM permissions, event integration, monitoring, controlled packet-level testing and operational safeguards.

Future Improvements

Potential improvements include:

- Deploying the architecture in a real AWS test VPC.
- Integrating actual AWS VPC Flow Logs.
- Deploying and validating the event-driven pipeline in a real AWS test environment.
- Improving flow aggregation and cumulative byte-count handling.
- Making HOME_NET and NACL configuration environment-driven.
- Expanding automated unit and regression test coverage.
- Integrating CloudWatch monitoring and alerting.
- Measuring end-to-end detection-to-remediation latency.
- Validating packet-level NACL enforcement in an isolated AWS test environment.
- Introducing approval workflows for higher-risk containment actions.

Conclusion

This project demonstrates a practical laboratory implementation of network intrusion detection, flow analysis, security alert processing and controlled cloud network remediation.

It combines Suricata, Python, Boto3 and LocalStack to demonstrate how suspicious network activity can be identified, analysed and translated into validated NACL remediation operations.

The project also emphasises safe testing practices, protected infrastructure, controlled remediation and transparent reporting of simulation limitations.

The result is a foundation for further development into a production-grade cloud network security monitoring and automated response architecture.

---

Project: Cloud Network Security — Automated VPC Flow Log Inspection, Suricata NIDS and Event-Driven NACL Threat Containment

Repository: https://github.com/Raheemolaitan/cloud-network-nids-remediation

Author: Raheem Olaitan Abdulrasheed

Training: Bincom Dev Center

## Network Flow Logger and Firewall Verdict Correlation

The project includes a Python-based network flow logger and firewall verdict processing pipeline.

### Implemented Components

- `flow_logger/flow_logger.py`: Captures live IPv4 and IPv6 packets on the configured laboratory interface.
- Records source and destination IP addresses, ports, protocol, packet size, timestamp and interface.
- Aggregates directional network flows using a five-tuple and a 60-second inactivity timeout.
- Saves packet records to `logs/network_flows.jsonl`.
- Saves aggregated flow records to `logs/network_flows_aggregated.jsonl`.
- `scripts/parse_firewall_verdicts.py`: Parses kernel firewall log entries into structured JSONL ACCEPT and REJECT records.
- `scripts/correlate_firewall_verdicts.py`: Matches packet records against firewall verdict records using flow attributes and a five-second timestamp window.

### Firewall Logging Validation

Firewall logging was tested using a separate nftables table named `cloud_network_security`.

The laboratory tests included:

- ICMP traffic from Kali Linux (`10.0.3.15`) to Ubuntu (`10.0.3.20`).
- Accepted incoming traffic recorded with an ACCEPT log prefix.
- A temporary TCP rejection test targeting port `44445`.
- Verification that the rejected TCP SYN packet was recorded with a REJECT log prefix.
- Removal of the temporary rejection test chain after validation.

The temporary rejection rule was used only for testing and was removed after the test.

### Observed Correlation Results

During the latest recorded test run:

| Metric | Result |
|---|---:|
| Packet records processed | 59 |
| ACCEPT matches | 9 |
| REJECT matches | 2 |
| PENDING_VERDICT records | 48 |
| Firewall verdict records parsed | 16 |

These results demonstrate successful matching for some observed packets. They do not demonstrate complete packet-to-firewall-verdict coverage.

### Known Limitations

- Firewall logging currently observes selected incoming and outgoing traffic on the laboratory interface. It does not provide complete visibility into all forwarded traffic or every firewall decision.
- The ACCEPT observation rules record traffic reaching their observation chains; they are not a universal record of every possible firewall verdict.
- The correlation script uses an exact directional flow match and a five-second timestamp window. Packets without a matching firewall record remain `PENDING_VERDICT`.
- The parser and correlation scripts are currently run manually rather than through a continuous event-driven pipeline.
- Packet-level verdict correlation has not been validated for every protocol, direction or traffic path.
- The aggregated flow records do not yet receive individual firewall verdicts.
- The latest correlation counts are laboratory test observations, not production performance benchmarks.

### Future Improvements

- Add complete and carefully validated firewall verdict coverage for INPUT, OUTPUT and FORWARD traffic.
- Improve correlation using packet identifiers or connection tracking where available.
- Automate log ingestion and verdict correlation.
- Add automated tests for parser accuracy, correlation edge cases and firewall rule behaviour.
- Integrate firewall verdicts with aggregated flow records.
- Validate the complete pipeline in an isolated AWS test VPC.
