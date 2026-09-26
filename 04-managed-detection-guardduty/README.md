# Managed Detection vs. the Attacks: GuardDuty + Security Hub

**Objective:** point AWS's managed threat-detection (Amazon GuardDuty) and its aggregator
(AWS Security Hub) at the same account the Phase-2 attacks run in, and measure what they catch
versus the hand-rolled CloudTrail metric-filter rules from
[`03-iam-privesc-passrole-lambda`](../03-iam-privesc-passrole-lambda/) (Phase 3a). The result is
the point: managed detection is **not a superset** of custom detection — it catches some things
the custom rules can't and misses the one they were built for.
**AWS services:** GuardDuty, Security Hub, IAM, Lambda, CloudTrail.

> This is a **Detect**-stage write-up. It reuses the Phase-2 privesc lab (misconfig D +
> primitive C) unchanged and adds managed detection alongside the Phase-3a custom rules, so the
> two detection approaches see the identical attack.

## Setup

Enable both services in the operating region. **Skip default standards** — the
GuardDuty→Security Hub finding flow does not depend on them, and enabling them creates managed
AWS Config rules that must be torn down in the right order (see *Teardown*, below) and mostly
report `NO_DATA` without an AWS Config recorder running:

```
# GuardDuty (15-min is the update-publish cadence, not a cost lever)
aws guardduty create-detector --enable \
    --finding-publishing-frequency FIFTEEN_MINUTES --region us-east-2

# Security Hub, WITHOUT default standards
aws securityhub enable-security-hub --no-enable-default-standards --region us-east-2
```

The GuardDuty→Security Hub integration is **auto-enabled** once both are on in the same
account+region — no accept/subscribe step. Confirm the product subscription registered:

```
$ aws securityhub list-enabled-products-for-import --region us-east-2
    ...:product-subscription/aws/guardduty     # findings will flow here (~5 min)
```

## The test

Two attacks, one account, both detection stacks watching:

1. The **PassRole→Lambda privesc** from Phase 2 (low-priv user → `AdministratorAccess`), the
   exact chain the Phase-3a CloudTrail rules were written for.
2. A **recon sweep issued from a Kali Linux host** using a low-priv access key — the "attacker
   is on a pentest box" case, which the custom CloudTrail rules were *not* written for.

## Result 1 — the clean privesc: GuardDuty null

After running the full PassRole→Lambda escalation, GuardDuty produced **zero findings** — checked
repeatedly over ~4 hours. CloudTrail confirmed the attack landed (`CreateFunction20150331` by the
low-priv user, the AssumeRole chain, the `AttachUserPolicy`), so the signal existed; GuardDuty
simply did not flag it.

Why: GuardDuty's IAM privilege-escalation finding is
`PrivilegeEscalation:IAMUser/AnomalousBehavior`, and its description states it is *"identified as
anomalous by GuardDuty's anomaly detection machine learning (ML) model."* That model builds a
per-principal behavioral baseline over a learning period (days). A **freshly enabled detector has
no baseline**, and a single, clean, one-shot privesc from a normal-looking API sequence matches no
signature-based finding type. So the miss is **structural for a new detector**, not a wait-longer
lag.

This is exactly the gap the Phase-3a hand-rolled rules close: their metric filters match the
attack's *own API calls* (`CreateFunction` passing the exec role; `AttachUserPolicy` of
`AdministratorAccess` with the Lambda-exec `sessionIssuer`) deterministically, on the first
occurrence, with no baseline. Custom detection caught what managed detection's ML did not.

## Result 2 — the Kali recon: GuardDuty deterministic catch

Running the same low-priv key's recon calls **from a Kali Linux host** produced GuardDuty findings
within ~15–18 minutes:

```
$ aws guardduty get-findings --detector-id <DETECTOR_ID> --region us-east-2 --finding-ids ...
    PenTest:IAMUser/KaliLinux   sev=5.0   principal=sigsec-lab-lowpriv
    PenTest:IAMUser/KaliLinux   sev=5.0   principal=sigsec-lab-lowpriv
```

Finding titles, verbatim: *"The API DescribeInstances was invoked from a Kali Linux computer"* and
*"…ListRoles… from a Kali Linux computer"* (source IP `<LAB_EGRESS_IP>`, caller type "Remote IP").
`PenTest:IAMUser/KaliLinux` is **signature-based, not ML** — its description carries none of the
anomaly-model language the `*/AnomalousBehavior` types do — so it fires deterministically on the
first matching call, no baseline required. The recon calls all returned `AccessDenied` (the key is
low-priv); the finding fires on *who/what is calling*, not on the call succeeding.

Both findings flowed through to Security Hub as aggregated `GuardDuty` findings (~9 min after
creation), confirming the enable→integrate→aggregate path end to end:

```
$ aws securityhub get-findings --region us-east-2 \
    --filters '{"ProductName":[{"Value":"GuardDuty","Comparison":"EQUALS"}]}'
    GuardDuty  MEDIUM  The API DescribeInstances was invoked from a Kali Linux computer.
    GuardDuty  MEDIUM  The API ListRoles was invoked from a Kali Linux computer.
```

## What this establishes

Managed and custom detection are **complementary layers, not substitutes**:

| | Clean PassRole→Lambda privesc | Recon from a Kali host |
|---|---|---|
| **GuardDuty (managed)** | ❌ null — ML finding needs a baseline a fresh detector lacks | ✅ `PenTest:IAMUser/KaliLinux`, deterministic, ~15 min |
| **CloudTrail metric filters (Phase 3a, custom)** | ✅ deterministic, first occurrence | ❌ not written for it (no rule keys on caller OS) |

GuardDuty gives immediate, zero-maintenance coverage of tooling/IP signatures (Kali/Parrot/Pentoo,
Tor, malicious-IP, custom threat lists) and — once its models have learned — anomaly coverage. But
on day one it will not catch a clean, deterministic privesc; the CloudTrail metric-filter rules
will. A real detection posture runs both.

## Operational gotchas (learned live, redacted)

- **Teardown ORDER is load-bearing.** If default standards were enabled, disable them
  (`batch-disable-standards`) and confirm the `securityhub-*` AWS Config rules are gone *before*
  `disable-security-hub`. AWS's own doc: if the hub is disabled while standards are still on,
  those Config rules can be **orphaned** and require an AWS Support ticket to delete — a silent
  biller. (Avoided entirely by not enabling standards.)
- **The `service.additionalInfo.sample` finding filter does not work**, and sample findings carry
  **no `[SAMPLE]` title prefix** — the `sample:true` flag is buried inside a stringified
  `Service.AdditionalInfo.Value` blob. To separate injected sample findings from real ones,
  **archive the samples** after validating the pipeline, then filter real findings with
  `service.archived = false` (a criterion GuardDuty *does* support).
- **`create-sample-findings` validates every type and rejects the whole batch on one bad string**
  (`PrivilegeEscalation:IAMUser/AdministrativePermissions` is not a valid sample type; the
  `*/AnomalousBehavior` privesc type is the real one).
- **The 30-day free trial is one calendar window per service, per account, per region**, consumed
  at first enable and not reset by disabling — plan all bursts inside it.
- **Security Hub now bills resource-based** (per EC2 instance / Lambda / IAM resource per month),
  not per-finding — "idle = ~$0" holds only during the trial or with near-zero running resources.

## Teardown

Detonate → detect → **tear down** so nothing bills between sessions:

```
aws securityhub disable-security-hub --region us-east-2
aws guardduty delete-detector --detector-id <DETECTOR_ID> --region us-east-2
```

Then verify, don't assume — `list-detectors` empty, `describe-hub` returns
`InvalidAccessException` (not subscribed), no `securityhub-*` Config rules, no AWS Config recorder
left running. A correct teardown of both = `$0` going forward.

## Detection

_(this write-up **is** the Detect-stage analysis)_ — the managed-vs-custom coverage matrix above is
the deliverable. The custom CloudTrail rules are in
[`03-iam-privesc-passrole-lambda`](../03-iam-privesc-passrole-lambda/#detection).

## Remediation

_(Prevent, Phase 4)_ — Run **layered detection**: GuardDuty for signature/anomaly coverage of the
whole account, plus CloudTrail metric-filter (or a SIEM) rules for the specific attack logic
GuardDuty's ML won't catch on a clean first occurrence. Add GuardDuty **suppression rules** for
known-benign sources rather than disabling finding types, and — for anomaly coverage to be real —
keep the detector enabled long enough to build a baseline instead of standing it up only per-burst.
