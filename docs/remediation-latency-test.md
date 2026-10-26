# NACL Remediation Latency Test

## Objective
Measure the time taken by the NACL remediation function to validate a dedicated Network ACL and create an outbound DENY rule in LocalStack.

## Test Environment
- Platform: Ubuntu 24.04.5 LTS virtual machine
- AWS-compatible environment: LocalStack 4.8.1
- Region: us-east-1
- Network ACL: acl-d636745fd2155230f
- Dedicated subnet: subnet-00756e574718220ef

## Test Procedure
A controlled Python test directly invoked the `create_deny_rule()` function using a reserved TEST-NET-3 destination address. The elapsed time was measured with Python's `time.perf_counter()`.

## Result
- Test destination: 203.0.113.88/32
- Direction: Outbound
- Action: DENY
- Protocol: All (-1)
- Rule number: 102
- Initial measured function execution time: 156.329 milliseconds
- Result: Successful
- Additional measurements: 3 successful repetitions

The rule was independently verified using the AWS CLI `describe-network-acls` command. The returned entry confirmed the expected destination CIDR, outbound direction, DENY action, protocol, and rule number.

## Interpretation and Limitations
The initial measurement of 156.329 ms was followed by three additional measurements. Across all four samples, the average was 98.911 ms and the median was 94.471 ms. Each measurement covers the complete `create_deny_rule()` function, including NACL lookup, validation operations, and the rule-creation API request.

This is not an end-to-end detection-to-containment measurement. It excludes Suricata detection time, parser processing, event transport, Lambda invocation overhead, and real AWS network data-plane enforcement.

The test ran against LocalStack. Successful API verification does not prove that real network packets were blocked. The destination address belongs to the reserved TEST-NET-3 documentation range and is not a real malicious destination.

Automatic containment remains disabled. This was an explicitly initiated controlled test, not automatic remediation triggered by a live alert.

## Conclusion
The initial controlled test successfully created and independently verified an outbound DENY entry in the dedicated LocalStack Network ACL. Three additional measurements were completed successfully, producing an average remediation-function execution time of 98.911 ms and a median of 94.471 ms.

## Repeated Latency Measurements

Three additional controlled measurements were performed using temporary TEST-NET-3 destination addresses. Each temporary outbound DENY rule was deleted immediately after its measurement.

| Measurement | Destination | Latency |
|---|---|---:|
| Original | 203.0.113.88 | 156.329 ms |
| Repeat 1 | 203.0.113.89 | 50.374 ms |
| Repeat 2 | 203.0.113.90 | 82.038 ms |
| Repeat 3 | 203.0.113.91 | 106.904 ms |

### Summary Statistics

- Successful measurements: 4
- Average: 98.911 ms
- Median: 94.471 ms
- Minimum: 50.374 ms
- Maximum: 156.329 ms

The average and median were calculated across all four measurements. The variation indicates that LocalStack API response time is not constant. These results are preliminary and should not be treated as a production AWS performance benchmark.

### Cleanup Verification

An independent AWS CLI query confirmed that the original outbound DENY rule for 203.0.113.88/32 remained present as rule 102. The three temporary rules for .89, .90, and .91 were absent after cleanup.

## Updated Conclusion

Four successful controlled measurements produced an average NACL remediation-function execution time of 98.911 ms and a median of 94.471 ms in LocalStack. The temporary test rules were removed and independently verified, while the original test rule was preserved. This demonstrates successful, repeatable API-level NACL remediation in the simulated environment, not real AWS packet enforcement or end-to-end detection-to-containment performance.
