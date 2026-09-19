# sigsec-cloud-lab

A hands-on cloud purple-team lab: build a realistic AWS/Azure misconfiguration,
attack it, detect the attack, then prevent it. Each exercise is a self-contained
write-up backed by infrastructure-as-code, with all account IDs, ARNs, and
credentials redacted.

## The map: attack → detect → prevent

| Stage | What it covers |
|-------|----------------|
| **Attack** | The misconfig and a runnable exploit path (IAM privesc, over-broad trust, PassRole chains, ...). |
| **Detect** | The log signal the attack leaves and the detection that fires on it (CloudTrail, Entra sign-in/audit → SIEM). |
| **Prevent** | The control that closes the gap (least-privilege policy, SCP/Conditional Access, guardrail). |

## Phases

1. **Foundation** — toolchain, this repo, reusable IAM attack primitives, first CloudGoat scenario, Entra hybrid-identity foundation.
2. **Exploit** — attack the Phase-1 primitives and expand the scenario library.
3. **Detect** — wire logs to detections; write the "Detection" section of each attack.
4. **Prevent** — least-privilege remediations and guardrails; write the "Remediation" section.

Write-ups follow [`TEMPLATE.md`](./TEMPLATE.md).

## Ethics & scope

All exercises run against my own AWS and Azure accounts, under the
[AWS Customer Support Policy for Penetration Testing](https://aws.amazon.com/security/penetration-testing/).
No third-party systems are targeted.
