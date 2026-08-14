# Storage: secure operation patterns

Scope: object storage (s3, s3api, s3control, s3tables, s3outposts), block and file
storage (ebs, efs, fsx), archival (glacier), backup and disaster recovery (backup,
backup-gateway, backupsearch), hybrid and edge (storagegateway, snowball,
snow-device-management).

## Services covered

- **s3 / s3api**: buckets and objects; s3 is the curated high-level layer (cp, sync, rm), s3api is the raw API. Most exposure-boundary risk in this domain lives here (bucket policies, ACLs, public access block, website hosting).
- **s3control**: account-level S3 features: access points, Multi-Region Access Points, Batch Operations jobs, Access Grants (a credential-vending system), Storage Lens.
- **s3tables**: Iceberg table buckets, namespaces, tables, table policies, replication, record expiration.
- **efs**: NFS file systems, mount targets, access points, file system policies, replication.
- **fsx**: managed Windows, Lustre, ONTAP, and OpenZFS file systems, volumes, snapshots, backups, data repository associations.
- **backup**: centralized backup plans, vaults, recovery points, vault locks, restore testing, legal holds.
- **glacier**: legacy vault-based archival; retrieval jobs, vault locks, vault policies.
- **storagegateway**: on-premises gateways (tape, volume, file); shares, tapes, cache, CHAP credentials, domain join.
- **ebs**: direct snapshot block APIs (start, put block, complete, diff).
- Long tail: backup-gateway (VMware backup gateways), backupsearch (search inside recovery points), s3outposts (endpoints), snowball and snow-device-management (physical device jobs, spend-committing).

## Querying safely

Always bound listings. Object listings especially can return millions of keys.

```bash
# S3: never dump a whole bucket; scope by prefix and cap the page
aws s3api list-objects-v2 --bucket BUCKET --prefix logs/2026/08/ --max-items 100 \
  --query "Contents[].{Key:Key,Size:Size,Modified:LastModified}"
aws s3 ls s3://BUCKET/prefix/ --page-size 200          # no --recursive on large trees
aws s3api list-buckets --query "Buckets[].Name" --max-items 50

# Exposure posture of a bucket, read-only triple check
aws s3api get-public-access-block --bucket BUCKET
aws s3api get-bucket-policy-status --bucket BUCKET --query PolicyStatus
aws s3api get-bucket-acl --bucket BUCKET --query "Grants[?Grantee.URI!=null]"

# Object metadata without fetching the body
aws s3api head-object --bucket BUCKET --key KEY

# s3control: account-wide posture
aws s3control get-public-access-block --account-id ACCOUNT
aws s3control list-access-points --account-id ACCOUNT --bucket BUCKET --max-items 50
aws s3control list-jobs --account-id ACCOUNT --job-statuses Active Suspended --max-items 20

# EFS / FSx: server-side filters first
aws efs describe-file-systems --file-system-id fs-0abc --query "FileSystems[].{Id:FileSystemId,State:LifeCycleState,Policy:BackupPolicy}"
aws efs describe-mount-targets --file-system-id fs-0abc --max-items 20
aws fsx describe-file-systems --file-system-ids fs-0abc \
  --query "FileSystems[].{Id:FileSystemId,Type:FileSystemType,State:Lifecycle}"
aws fsx describe-backups --filters Name=file-system-id,Values=fs-0abc --max-results 20

# Backup: scope by vault or resource, never all recovery points at once
aws backup list-recovery-points-by-backup-vault --backup-vault-name VAULT --max-results 50 \
  --query "RecoveryPoints[].{Arn:RecoveryPointArn,Created:CreationDate,Status:Status}"
aws backup list-backup-jobs --by-state FAILED --by-created-after 2026-08-01 --max-results 50

# Storage Gateway
aws storagegateway list-gateways --limit 50
aws storagegateway describe-gateway-information --gateway-arn ARN
```

Reads that are not neutral: `s3 presign` mints a shareable URL (treat the output as a
secret), `s3api create-session`, `s3control get-data-access`, `snowball
get-job-manifest` and `get-job-unlock-code`, and `storagegateway
describe-chap-credentials` all return credential material. Run them only with a
documented reason and never paste their output into logs or tickets.

## Mutating safely

Dry-run support is rare in this domain. Only the high-level s3 commands have it:

```bash
aws s3 cp local/ s3://BUCKET/prefix/ --recursive --dryrun     # always preview first
aws s3 sync local/ s3://BUCKET/prefix/ --dryrun               # mandatory before --delete
aws s3 rm s3://BUCKET/prefix/ --recursive --dryrun            # review the full kill list
```

There is no dry-run for s3api, efs, fsx, backup, or storagegateway mutations. The
staged-flow substitutes:

- **Read-modify-write for full-replace configs.** `put-bucket-lifecycle-configuration`, `put-bucket-replication`, `put-bucket-cors`, `put-bucket-notification-configuration`, and the s3control and s3tables equivalents replace the entire configuration. Always `get` the current document, edit it locally, then `put` the merged result. A put with only your new rule silently deletes every existing rule.
- **Policies from files, validated first.** Write bucket, access point, vault, and file system policies to a JSON file, lint them (`python3 -m json.tool`), diff against the current policy, then apply: `aws s3api put-bucket-policy --bucket BUCKET --policy file://policy.json`.
- **One target per command.** Never loop a destructive verb over a listing in a single shell pipeline. Materialize the target list to a file, review it, then act on each entry.
- **Tag at creation time:**

```bash
aws s3api create-bucket --bucket NAME --region us-east-1   # then immediately:
aws s3api put-bucket-tagging --bucket NAME --tagging 'TagSet=[{Key=env,Value=prod},{Key=owner,Value=team}]'
aws s3api put-public-access-block --bucket NAME --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws efs create-file-system --encrypted --backup --tags Key=env,Value=prod Key=owner,Value=team
aws fsx create-file-system --file-system-type OPENZFS ... --tags Key=env,Value=prod
aws backup create-backup-vault --backup-vault-name NAME --backup-vault-tags env=prod
```

- **S3 Batch Operations**: create jobs with `--no-confirmation-required` absent (the default requires confirmation), review with `describe-job`, then release with `update-job-status --requested-job-status Ready`. A batch job can rewrite tags, ACLs, retention, or invoke functions across billions of objects; treat job creation as a privileged act.
- **Object Lock and vault locks are one-way doors.** Compliance-mode retention (`put-object-retention`, `put-object-lock-configuration`), Backup Vault Lock in compliance mode, and `glacier complete-vault-lock` cannot be undone by anyone, including the root user. Rehearse on a scratch resource, verify the policy text, and get sign-off before applying.

## Destructive traps

| Command                                                                               | Why dangerous                                                                                                              | Safe procedure                                                                                                                                       |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `s3 rm --recursive`, `s3api delete-objects`                                           | Permanent mass deletion; without versioning there is no recovery                                                           | `--dryrun` (s3) or list keys to a file first; confirm versioning status with `get-bucket-versioning`; delete a bounded prefix, never the bucket root |
| `s3 rb --force`                                                                       | Empties then deletes the bucket in one shot                                                                                | Never use `--force`; empty deliberately, verify emptiness with `list-objects-v2 --max-items 1`, then `delete-bucket`                                 |
| `s3 sync --delete`                                                                    | Deletes destination objects missing from source; a wrong source path wipes the destination                                 | Run the identical command with `--dryrun` and read every DELETE line before the real run                                                             |
| `s3 cp` / `s3api put-object` onto existing keys                                       | Silently overwrites; unversioned buckets lose the prior object                                                             | `head-object` the destination first, or enable versioning before bulk writes                                                                         |
| `s3api delete-public-access-block`, permissive `put-bucket-policy` / `put-bucket-acl` | Opens the bucket to public or cross-account access                                                                         | Treat as an exposure change: peer review the policy diff, re-check `get-bucket-policy-status` after                                                  |
| `s3api put-bucket-lifecycle-configuration`                                            | Full replace; expiration rules mass-delete objects on a delay, damage appears days later                                   | Get current config, merge, apply, read back; double-check `Expiration` and `NoncurrentVersionExpiration` day counts                                  |
| `s3api put-bucket-versioning` (Suspended)                                             | Later overwrites and deletes become unrecoverable                                                                          | Confirm why suspension is needed; prefer lifecycle rules on noncurrent versions instead                                                              |
| `fsx delete-file-system`, `fsx delete-volume`                                         | All data gone; final backup behavior varies by type and flags (`SkipFinalBackup`)                                          | Take an explicit `create-backup` first, verify it is AVAILABLE, never pass skip-final-backup flags                                                   |
| `fsx restore-volume-from-snapshot`                                                    | Reverts the volume, discarding everything written since the snapshot; options can delete intermediate snapshots and clones | Snapshot current state first; enumerate `--options` explicitly; confirm the snapshot ID against `describe-snapshots`                                 |
| `efs delete-file-system`                                                              | Irreversible data loss; requires mount targets deleted first, which already severs clients                                 | Check `describe-mount-targets` for live clients, confirm a recent AWS Backup recovery point exists                                                   |
| `backup delete-recovery-point`, `glacier delete-archive`                              | Destroys the backup itself; this is the blast radius of last resort                                                        | Verify another recovery point or replica covers the data; never bulk-delete recovery points to save cost without a retention decision on record      |
| `storagegateway disable-gateway`                                                      | Irreversible; a disabled gateway can never be re-enabled                                                                   | Only for a dead tape gateway during recovery; confirm the gateway is genuinely unreachable first                                                     |
| `storagegateway reset-cache`                                                          | Any cached data not yet uploaded to AWS is lost                                                                            | Check upload status (CloudWatch CachePercentDirty near zero) before resetting                                                                        |
| `storagegateway shutdown-gateway`                                                     | Halts all I/O for every share, volume, and tape on the gateway                                                             | Quiesce clients first; schedule a window; prefer `update-maintenance-start-time` for routine work                                                    |
| `glacier initiate-job` (Expedited)                                                    | Retrieval tier commits real spend per request                                                                              | Default to Standard or Bulk tier; Expedited only with a documented cost decision                                                                     |
| `snowball create-job` / `create-cluster` / `create-long-term-pricing`                 | Orders billed physical hardware; long-term pricing bills 1 or 3 years upfront                                              | Confirm the order with the budget owner before running                                                                                               |

## Waiters and timing

Available waiters in this domain:

| Service | Waiter                            | Delay x attempts | Max wait |
| ------- | --------------------------------- | ---------------- | -------- |
| s3api   | bucket-exists / bucket-not-exists | 5s x 20          | 100s     |
| s3api   | object-exists / object-not-exists | 5s x 20          | 100s     |
| glacier | vault-exists / vault-not-exists   | 3s x 15          | 45s      |

```bash
aws s3api wait bucket-exists --bucket NAME
aws s3api wait object-not-exists --bucket NAME --key KEY
```

No waiters exist for efs, fsx, backup, or storagegateway. Poll the describe call
with a bounded loop, never an unbounded `while true`:

```bash
# EFS: lifeCycleState creating -> available (typically under a minute)
for i in $(seq 1 20); do
  s=$(aws efs describe-file-systems --file-system-id fs-0abc --query "FileSystems[0].LifeCycleState" --output text)
  [ "$s" = "available" ] && break; sleep 15
done

# FSx: Lifecycle CREATING -> AVAILABLE (can take 20+ minutes; poll wide, cap attempts)
# poll: aws fsx describe-file-systems --file-system-ids ID --query "FileSystems[0].Lifecycle"

# Backup jobs: CREATED/RUNNING -> COMPLETED
# poll: aws backup describe-backup-job --backup-job-id ID --query State
# Restore jobs: aws backup describe-restore-job --restore-job-id ID --query Status

# S3 Batch Operations: aws s3control describe-job --account-id A --job-id J --query "Job.Status"
# Glacier retrieval jobs take 3 to 12 hours (Standard): poll describe-job --query Completed
# at minutes-scale intervals, or rely on the SNS notification instead of polling.
```

Timing notes: Glacier and S3 Glacier-class restores are hours-scale, do not
tight-poll them. FSx storage capacity updates run a long optimization phase after
the API returns success. `delete-bucket` after emptying a versioned bucket can fail
until delete markers are also removed.

## Verification after change

Prove every mutation with a read-back, and check the exposure posture after any
policy or ACL change:

```bash
# Object writes and deletes
aws s3api head-object --bucket BUCKET --key KEY                       # exists, ETag, size
aws s3api list-object-versions --bucket BUCKET --prefix KEY --max-items 5   # delete marker present?

# Policy and exposure changes: read back AND re-evaluate status
aws s3api get-bucket-policy --bucket BUCKET --query Policy --output text | python3 -m json.tool
aws s3api get-bucket-policy-status --bucket BUCKET     # IsPublic must match intent
aws s3api get-public-access-block --bucket BUCKET
aws s3api get-bucket-encryption --bucket BUCKET
aws s3api get-bucket-versioning --bucket BUCKET
aws s3api get-bucket-lifecycle-configuration --bucket BUCKET          # rule count as expected

# Access points and grants
aws s3control get-access-point-policy-status --account-id A --name AP
aws s3control list-access-grants --account-id A --max-items 20

# EFS / FSx
aws efs describe-file-systems --file-system-id fs-0abc --query "FileSystems[0].LifeCycleState"
aws efs describe-file-system-policy --file-system-id fs-0abc
aws fsx describe-file-systems --file-system-ids fs-0abc --query "FileSystems[0].Lifecycle"
aws fsx describe-backups --backup-ids backup-0abc --query "Backups[0].Lifecycle"   # AVAILABLE

# Backup: the job finishing is not enough, confirm the recovery point
aws backup describe-backup-job --backup-job-id ID --query "{State:State,RP:RecoveryPointArn}"
aws backup describe-recovery-point --backup-vault-name VAULT --recovery-point-arn ARN --query Status
aws backup describe-backup-vault --backup-vault-name VAULT --query "{Locked:Locked,MinRetentionDays:MinRetentionDays}"

# Storage Gateway
aws storagegateway describe-gateway-information --gateway-arn ARN --query "{State:GatewayState,Running:GatewayOperationalState}"
aws storagegateway describe-smb-file-shares --file-share-arn-list ARN
```

For deletions, verify absence: `head-object` returning 404, `describe-file-systems`
returning FileSystemNotFound, `list-recovery-points-by-backup-vault` no longer
listing the ARN. For lifecycle and replication configs, read the configuration back
and count the rules; a successful HTTP 200 on the put does not prove the document
you intended is the one stored.
