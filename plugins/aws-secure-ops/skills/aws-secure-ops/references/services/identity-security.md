# Identity and Security: secure operation patterns

This domain concentrates the highest-consequence surface of the CLI: credential issuance (STS, SSO OIDC, Cognito), permission definition (IAM, Organizations, SSO Admin, Verified Permissions), key and secret custody (KMS, Secrets Manager, ACM, ACM PCA, CloudHSM, Payment Cryptography), perimeter defense (WAF, Shield, Firewall Manager), and detection (GuardDuty, Security Hub, Inspector, Macie, Detective, Access Analyzer). Mistakes here do not break one workload, they change who can do what everywhere. Treat every mutation as a permission or trust change until proven otherwise.

## Services covered

- **iam**: users, roles, policies, boundaries, credentials, federation providers.
- **sts**: temporary credential issuance and identity verification.
- **kms**: key lifecycle, grants, key policies, data-plane crypto.
- **secretsmanager**: secret storage, versioning, rotation, replication, resource policies.
- **organizations**: accounts, OUs, SCPs and other policy types, delegated admins.
- **sso-admin / identitystore / sso / sso-oidc**: Identity Center permission sets, assignments, users, groups, token issuance.
- **cognito-idp / cognito-identity / cognito-sync**: user pools, identity pools, end-user auth flows.
- **acm / acm-pca**: public and private certificate lifecycle.
- **wafv2 (plus legacy waf, waf-regional)**: web ACLs, rule groups, IP sets, logging.
- **guardduty / securityhub / inspector2 / macie2 / detective / accessanalyzer**: detection and posture; member and delegated-admin wiring.
- **shield / fms**: DDoS protection and org-wide firewall policy enforcement.
- **ram**: cross-account resource shares.
- **ds / ds-data**: managed Microsoft AD and AD Connector, directory users and groups.
- **rolesanywhere**: certificate-based access for non-AWS workloads (trust anchors, profiles).
- Long tail: account, cloudhsm, cloudhsmv2, detective, fms, inspector (classic), payment-cryptography, payment-cryptography-data, pca-connector-ad, pca-connector-scep, security-ir, signer, verifiedpermissions.

## Querying safely

Reads in this domain are cheap and safe with two exceptions: operations that emit credential or secret material (see traps), and unbounded dumps of large principal sets. Always bound list calls.

IAM, bounded and server-filtered:

```bash
aws iam list-roles --path-prefix /service-role/ --max-items 50 \
  --query 'Roles[].{Name:RoleName,Created:CreateDate}'
aws iam list-attached-role-policies --role-name MyRole
aws iam get-role --role-name MyRole --query 'Role.AssumeRolePolicyDocument'
aws iam list-entities-for-policy --policy-arn arn:aws:iam::ACCT:policy/MyPolicy --max-items 50
aws iam get-account-summary          # quotas and usage counts, one call
aws iam generate-service-last-accessed-details --arn arn:aws:iam::ACCT:role/MyRole
```

Prefer `iam simulate-principal-policy` and `iam simulate-custom-policy` to answer "would this be allowed" instead of trial mutations: both are pure reads.

STS identity check (run before any mutation, it proves which principal acts):

```bash
aws sts get-caller-identity
aws sts get-access-key-info --access-key-id AKIA...   # maps a key to its account
```

KMS and Secrets Manager, metadata only:

```bash
aws kms list-keys --limit 50
aws kms describe-key --key-id alias/my-key --query 'KeyMetadata.{State:KeyState,Mgr:KeyManager,Spec:KeySpec}'
aws kms get-key-policy --key-id KEYID --policy-name default --output text
aws kms list-grants --key-id KEYID --limit 20
aws secretsmanager list-secrets --filters Key=name,Values=prod/ --max-items 50 \
  --query 'SecretList[].{Name:Name,Rotated:LastRotatedDate}'
aws secretsmanager describe-secret --secret-id prod/db   # metadata, never the value
```

`get-secret-value`, `batch-get-secret-value`, `kms decrypt`, and `kms generate-data-key` print secret material to the terminal and transcript. Call them only when the value itself is the deliverable, never "to check the secret exists" (use `describe-secret`).

Organizations and Identity Center:

```bash
aws organizations list-accounts --max-items 50 --query 'Accounts[].{Id:Id,Name:Name,State:Status}'
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --max-items 50
aws organizations list-targets-for-policy --policy-id p-xxxx
aws sso-admin list-permission-sets --instance-arn $SSO_ARN --max-results 50
aws sso-admin list-account-assignments --instance-arn $SSO_ARN \
  --account-id 111122223333 --permission-set-arn $PS_ARN
```

Detection suite, filter server-side, never pull all findings:

```bash
aws guardduty list-findings --detector-id $DID --max-results 25 \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
aws securityhub get-findings --max-items 25 --filters \
  '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}'
aws inspector2 list-findings --max-results 25 \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}'
aws accessanalyzer list-findings --analyzer-arn $ARN --max-results 25 \
  --filter '{"status":{"eq":["ACTIVE"]}}'
```

WAF reads need scope: `--scope REGIONAL` (or `CLOUDFRONT`, us-east-1 only):

```bash
aws wafv2 list-web-acls --scope REGIONAL
aws wafv2 get-web-acl --scope REGIONAL --name my-acl --id $ID \
  --query 'WebACL.Rules[].{Name:Name,Action:Action,Priority:Priority}'
aws wafv2 list-resources-for-web-acl --web-acl-arn $ACL_ARN
```

## Mutating safely

Almost nothing in this domain supports `--dry-run`. Substitutes, in order of preference:

1. **Simulate before granting**: `iam simulate-principal-policy` against the exact action list a new policy would allow or deny.
2. **Validate policy documents offline**: `aws accessanalyzer validate-policy --policy-document file://p.json --policy-type IDENTITY_POLICY` reports errors and security warnings without touching any principal. Use `check-no-new-access` to compare a candidate policy against the current one and `check-access-not-granted` to prove a policy cannot grant specific actions. `secretsmanager validate-resource-policy` does the same for secret policies.
3. **Stage on inert copies**: create a policy as a new version with `iam create-policy-version` WITHOUT `--set-as-default`, review, then promote with `iam set-default-policy-version`. Old versions remain for instant rollback.
4. **KMS key policy safety valve**: never apply a key policy without confirming it keeps your admin principal; `put-key-policy` with a policy that locks everyone out is only recoverable through AWS support. Pass `--bypass-policy-lockout-safety-check` never.

One target per command. Do not loop a mutation over principals from a list you have not printed and reviewed first.

Tag at creation time. Both syntaxes appear in this domain:

```bash
aws iam create-role --role-name app-reader \
  --assume-role-policy-document file://trust.json \
  --tags Key=owner,Value=team-x Key=purpose,Value=TICKET-123
aws kms create-key --description "app data key" \
  --tags TagKey=owner,TagValue=team-x
aws secretsmanager create-secret --name prod/app/db \
  --secret-string file://value.json --tags Key=owner,Value=team-x
aws wafv2 create-ip-set --scope REGIONAL --name blocklist \
  --ip-address-version IPV4 --addresses 192.0.2.0/24 --tags Key=owner,Value=team-x
```

Credential issuance is a mutation of the attack surface even when the API is a "read":

- `sts assume-role`: set `--duration-seconds` to the minimum needed and a `--role-session-name` that identifies the operator and ticket.
- `iam create-access-key`: the secret is shown once; write it directly to its destination, never to shell history or scratch files. A user may hold two keys, so rotation is create new, switch consumer, verify, delete old.
- `secretsmanager` rotation: prefer `rotate-secret` with a rotation lambda over manual `put-secret-value`; manual writes move the `AWSCURRENT` stage immediately.

Deletions that support a recovery window, always use it:

```bash
aws secretsmanager delete-secret --secret-id prod/app/db --recovery-window-in-days 30
aws kms schedule-key-deletion --key-id KEYID --pending-window-in-days 30
```

Never use `secretsmanager delete-secret --force-delete-without-recovery` unless the value is confirmed re-creatable, and never combine it with cross-region replicas without first `remove-regions-from-replication`.

WAF changes: `update-web-acl` and `update-rule-group` are full replacements, not merges. Fetch the current rules, obtain `LockToken` from the get call, edit, and send the complete rule set back. Sending a partial list silently drops every rule you omitted.

## Destructive traps

| Command                                                                                   | Why dangerous                                                                                               | Safe procedure                                                                                                                          |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `kms schedule-key-deletion`                                                               | After the pending window, every ciphertext under the key is permanently unreadable                          | Prefer `disable-key` first; run with encrypted-data inventory attached; 30-day window; know `cancel-key-deletion` exists                |
| `kms delete-imported-key-material`                                                        | Immediately unusable key; recoverable only by re-importing identical material                               | Confirm the original material is archived before deleting                                                                               |
| `kms disable-key` / `put-key-policy`                                                      | Instantly breaks every service decrypting with the key; bad policy can lock out all admins                  | Check `list-grants` and CloudTrail usage first; keep admin principal in every policy                                                    |
| `organizations close-account` / `leave-organization` / `remove-account-from-organization` | Account-level, largely irreversible, billing and access all change at once                                  | Written approval; verify account ID twice; confirm standalone billing prerequisites                                                     |
| `organizations detach-policy` / `disable-policy-type`                                     | Detaching an SCP or disabling the type removes guardrails from whole subtrees at once                       | List targets first; detach from one test OU; watch CloudTrail for newly allowed actions                                                 |
| `iam delete-role` (and `delete-user`)                                                     | Breaks every workload assuming the role; requires detaching policies, instance profiles first               | `generate-service-last-accessed-details` to prove it is unused; keep the trust and policy documents for rollback                        |
| `iam deactivate-mfa-device` / `delete-login-profile`                                      | Strips a human's second factor or console access; classic account-takeover step                             | Verify with the identity owner out-of-band before touching another principal's credentials                                              |
| `iam update-access-key --status Inactive`                                                 | Kills whatever automation still signs with the key                                                          | `get-access-key-last-used` first; deactivate, observe, then delete                                                                      |
| `sso-admin delete-permission-set` / `delete-account-assignment`                           | Removes workforce access across many accounts in one call                                                   | Enumerate `list-account-assignments` impact first; snapshot inline policy with `get-inline-policy-for-permission-set`                   |
| `cognito-idp delete-user-pool` / `delete-identity-pool`                                   | Deletes every end user, group, and federation config; no recycle bin                                        | Export users first; require the pool ID read back from a describe, never typed from memory                                              |
| `wafv2 delete-web-acl` / `disassociate-web-acl`                                           | Protected apps go straight to the internet unfiltered; disassociate looks harmless but removes the firewall | `list-resources-for-web-acl` first; move associations to a replacement ACL before deleting                                              |
| `shield delete-subscription` / `create-subscription`                                      | Deleting drops DDoS response mid-contract; creating commits a large monthly fee with auto-renewal           | Both need explicit budget-owner approval                                                                                                |
| `guardduty delete-detector` / `securityhub disable-security-hub` / `macie2 disable-macie` | Detection goes dark org-wide or account-wide; historical findings can be lost                               | Suspend instead where possible (`update-detector --no-enable`); export findings first                                                   |
| `acm delete-certificate` / `acm-pca delete-certificate-authority`                         | In-use cert breaks TLS; a deleted CA cannot validate or revoke its issued certs                             | `describe-certificate --query 'Certificate.InUseBy'` must be empty; CAs: disable first, use maximum `--permanent-deletion-time-in-days` |
| `ds delete-directory` / `delete-trust` / `disable-ldaps`                                  | Directory-joined workloads and trusts fail immediately; LDAPS downgrade sends cleartext                     | Take `create-snapshot` first; inventory joined instances; change auth settings in a maintenance window                                  |
| `ram delete-resource-share`                                                               | Consumers in other accounts lose access to shared subnets, rules, resolver rules instantly                  | `get-resource-share-associations` to list consumers; coordinate before deleting                                                         |
| `secretsmanager put-resource-policy` / `kms create-grant` / `*-permission-policy`         | Grants other principals, possibly other accounts, access to secret or key material                          | Validate the policy document; name exact principal ARNs, never `"AWS":"*"`                                                              |

## Waiters and timing

Available waiters in this domain (delay x attempts = max wait):

| Service | Waiter                                    | Timing             | Polls                                       |
| ------- | ----------------------------------------- | ------------------ | ------------------------------------------- |
| acm     | certificate-validated                     | 60s x 5 = 5 min    | describe-certificate                        |
| acm-pca | certificate-authority-csr-created         | 3s x 60 = 3 min    | get-certificate-authority-csr               |
| acm-pca | certificate-issued                        | 1s x 60 = 1 min    | get-certificate                             |
| acm-pca | audit-report-created                      | 3s x 60 = 3 min    | describe-certificate-authority-audit-report |
| iam     | role-exists / user-exists / policy-exists | 1s x 20 = 20 s     | get-role / get-user / get-policy            |
| iam     | instance-profile-exists                   | 1s x 40 = 40 s     | get-instance-profile                        |
| signer  | successful-signing-job                    | 20s x 25 = 8.3 min | describe-signing-job                        |
| macie2  | finding-revealed                          | 2s x 60 = 2 min    | get-sensitive-data-occurrences              |
| ds      | hybrid-ad-updated                         | 120s x 60 = 2 h    | describe-hybrid-ad-update                   |

```bash
aws iam wait role-exists --role-name app-reader
aws acm wait certificate-validated --certificate-arn $CERT_ARN   # DNS validation often exceeds 5 min; re-run at most twice
```

IAM is eventually consistent globally: a role that exists per the waiter may still fail `sts assume-role` for up to a minute or two. On `AccessDenied` immediately after creating IAM material, wait 30 seconds and retry twice before diagnosing policy.

Where no waiter exists, poll a bounded describe with explicit limits, never an open loop:

- KMS key state: `aws kms describe-key --query 'KeyMetadata.KeyState'` every 10 s, max 12 tries (states: Enabled, Disabled, PendingDeletion).
- Directory Service: `aws ds describe-directories --directory-ids $DID --query 'DirectoryDescriptions[0].Stage'` every 60 s, max 45 tries (creation runs 20 to 45 minutes).
- CloudHSM v2 cluster: `aws cloudhsmv2 describe-clusters --filters clusterIds=$CID --query 'Clusters[0].State'` every 60 s, max 30 tries.
- GuardDuty/Macie member wiring: re-run the corresponding get/describe once after 30 s, these settle quickly.
- WAF: changes are effective when the API returns; propagation to edge is seconds, no poll needed.

## Verification after change

Prove the mutation landed with a read-back, and prove the blast radius is what you intended.

```bash
# IAM: policy attached and effective
aws iam list-attached-role-policies --role-name app-reader
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCT:role/app-reader \
  --action-names s3:GetObject --resource-arns arn:aws:s3:::my-bucket/*
# and the negative case: an action it must NOT have
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCT:role/app-reader \
  --action-names iam:PassRole --query 'EvaluationResults[].EvalDecision'

# Credentials: new key active, old key gone
aws iam list-access-keys --user-name deploy-bot
aws sts get-caller-identity          # run under the new credential

# KMS: state, rotation, policy, grants
aws kms describe-key --key-id KEYID --query 'KeyMetadata.KeyState'
aws kms get-key-rotation-status --key-id KEYID
aws kms list-grants --key-id KEYID --limit 20

# Secrets Manager: stages moved, replication healthy, policy readable
aws secretsmanager describe-secret --secret-id prod/app/db \
  --query '{Stages:VersionIdsToStages,Repl:ReplicationStatus}'
aws secretsmanager get-resource-policy --secret-id prod/app/db

# Organizations: policy attached where intended and nowhere else
aws organizations list-targets-for-policy --policy-id p-xxxx
aws organizations list-policies-for-target --target-id ou-xxxx --filter SERVICE_CONTROL_POLICY

# Identity Center: assignment provisioned
aws sso-admin list-account-assignments --instance-arn $SSO_ARN \
  --account-id 111122223333 --permission-set-arn $PS_ARN

# WAF: rule set complete (count rules, compare to expected) and still associated
aws wafv2 get-web-acl --scope REGIONAL --name my-acl --id $ID \
  --query 'length(WebACL.Rules)'
aws wafv2 list-resources-for-web-acl --web-acl-arn $ACL_ARN

# Detection suite: still enabled after member or config changes
aws guardduty get-detector --detector-id $DID --query 'Status'
aws securityhub describe-hub
aws macie2 get-macie-session --query 'status'
```

After any permission or trust change, close the loop in CloudTrail: confirm your own mutation event is recorded, and for grants to other principals, watch for first use. An exposure change without a consumer is a standing risk; an exposure change with an unexpected consumer is an incident.
