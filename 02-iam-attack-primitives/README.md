# IAM Attack Primitives (reusable Phase-2 surface)

**Objective:** Stand up three deliberately-shaped IAM constructs that model common
privilege-escalation and trust misconfigurations, as reusable targets for the Phase-2
attack write-ups.
**AWS services:** IAM, STS, Lambda (Phase 2).
**IaC:** Terraform (`iam-primitives/`, account ID redacted). Deployed on demand and torn
down per session — they persist deliberately only as Phase-2's attack surface.

> **Status:** these are the *setup*. None is exploited here. A and C are Phase-2 targets
> (no credentials are minted, so neither is live-exploitable yet); B is deployed in its
> *remediated* form on purpose (see below). Attack write-ups land in Phase 2.

## Primitive A — over-privileged role, in-account assumable

```hcl
resource "aws_iam_role" "overpriv" {
  name = "sigsec-lab-overpriv"
  assume_role_policy = { Principal = { AWS = "arn:aws:iam::<ACCOUNT_ID>:root" }, Action = "sts:AssumeRole" }
}
# + attach arn:aws:iam::aws:policy/PowerUserAccess
```

**Misconfig:** a role carrying `PowerUserAccess` whose trust policy admits the whole
account root. It is *not* externally assumable — the risk is **blast-radius
amplification**: any in-account principal that can call `sts:AssumeRole` (or whose
credentials leak) inherits PowerUser across every service.

**Attack it enables:** a compromised low-value credential → `aws sts assume-role
--role-arn arn:aws:iam::<ACCOUNT_ID>:role/sigsec-lab-overpriv` → PowerUser. The lesson is
that an account-root trust turns *any* credential compromise into a near-admin one.

## Primitive B — cross-account trust (shown in its remediated form)

```hcl
resource "aws_iam_role" "xacct" {
  name = "sigsec-lab-xacct"
  assume_role_policy = {
    Principal = { AWS = "arn:aws:iam::<TRUSTED_ACCOUNT>:root" },
    Action    = "sts:AssumeRole",
    Condition = { StringEquals = { "sts:ExternalId" = "<EXTERNAL_ID>" } }
  }
}
```

**The anti-pattern (NOT deployed):** `Principal = "*"` with no condition — a globe-open
role any AWS account can assume, the classic **confused-deputy**. This repo deploys the
**fixed** form instead: trust scoped to one named account *and* gated on a secret
`sts:ExternalId`, with no permissions attached (belt-and-suspenders). It exists to
demonstrate the control, not to expose a live wildcard. The Phase-4 remediation write-up
contrasts the two directly.

## Primitive C — PassRole + Lambda privilege-escalation pair

```hcl
resource "aws_iam_user_policy" "privesc_pair" {
  user   = "sigsec-lab-lowpriv"
  policy = { Action = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], Resource = "*" }
}
```

**Misconfig:** a low-privilege user granted `iam:PassRole` + Lambda create/invoke on
`Resource = "*"`. This is a canonical escalation pair.

**Attack it enables:** create a Lambda function, **pass a higher-privileged role** to it,
invoke it → arbitrary code executes at that role's privilege. The `PassRole` wildcard is
the hinge: without a resource constraint, the user can hand *any* passable role to their
own code. No access key is minted here, so it is inert until Phase 2 provisions
credentials for `sigsec-lab-lowpriv`.

> **Phase 2 realization:** the "higher-privileged role" this needs must be *Lambda-assumable*
> — none of A/B is. Phase 2 adds that missing target as **misconfig D** (`sigsec-lab-lambda-exec`,
> trusts `lambda.amazonaws.com`, `IAMFullAccess`) and runs the full chain in
> [`03-iam-privesc-passrole-lambda`](../03-iam-privesc-passrole-lambda/).

## What the attacker gains

A → PowerUser across the account from any in-account foothold. B (in the anti-pattern
form) → cross-account assumption by an untrusted party. C → code execution at an
arbitrary passable role's privilege. Together they model the three ways IAM turns a
small foothold into account-wide control: over-broad trust, open cross-account trust, and
unconstrained `PassRole`.

## Detection

_(added in Phase 3)_ — CloudTrail signals: `sts:AssumeRole` to `sigsec-lab-overpriv` from
a non-administrative principal (A); `AssumeRole` events on the cross-account role from an
unexpected source account or without the ExternalId (B); `lambda:CreateFunction` +
`iam:PassRole` of a privileged role by `sigsec-lab-lowpriv`, followed by `InvokeFunction` (C).

## Remediation

_(added in Phase 4)_ — A: scope the role's trust to specific principals and replace
`PowerUserAccess` with a least-privilege policy. B: never use `Principal = "*"`; require a
named account **and** `sts:ExternalId` (the deployed form here is the target state). C:
constrain `iam:PassRole` to a specific role ARN and add a `PassedToService` /
`iam:AssociatedResourceArn` condition; scope Lambda actions.
