# Operation classes: the taxonomy behind the gate

Every operation the CLI can perform is assigned one class and one sensitivity
flag. The full assignment for the installed CLI lives in
`inventory/inventory.csv` (regenerate after CLI upgrades with
`scripts/build-inventory.py`); this file is the reasoning, the exceptions, and
the fallback for anything not yet in the inventory.

## Classes

| Class     | Definition                                                                  | Gate behavior                       |
| --------- | --------------------------------------------------------------------------- | ----------------------------------- |
| `read`    | No state change, no credential material                                     | Passes silently                     |
| `execute` | Side effect without infrastructure CRUD: invoke, send, publish, start a job | Purpose stamp required              |
| `create`  | Provisions a new resource                                                   | Stamp + tags + mutation ladder      |
| `modify`  | Changes an existing resource or its configuration                           | Stamp + mutation ladder             |
| `destroy` | Removes, terminates, or DISRUPTS a resource                                 | Stamp + ladder + human confirmation |

`sensitive=1` is orthogonal and forces human confirmation regardless of class.
An operation is sensitive when it:

- emits credential or secret material, or mints identity;
- changes a trust or exposure boundary: resource policies, ACLs, public
  sharing attributes, cross-account grants;
- commits spend (reservations, purchases, domain transfers);
- disrupts a running workload (stop, reboot, failover);
- degrades audit or security telemetry.

## Decision procedure for any command

1. Extract `service` and `operation` (CLI kebab-case).
2. Look them up: `grep -m1 "^<service>,<operation>," inventory/inventory.csv`.
3. On a miss (newer CLI, custom command), apply the verb rules below to the
   operation name; strip a leading `Batch`/`Admin` wrapper first.
4. No verb rule matches: treat as `modify` + `sensitive=1`, a guarded mutation,
   until documentation proves otherwise.
5. Apply flag-level escalations (below) on top of the class.

## Verb rules (first match wins)

- **destroy**: delete, terminate, purge, destroy, wipe, remove, revoke,
  deregister, release, retire, forget, deprecate, expire, evict, uninstall,
  unsubscribe, erase, reboot, failover, switchover, deprovision, restart
- **create**: create, register, allocate, provision, import, upload, clone,
  restore, launch, duplicate, renew, request, reserve, subscribe, invite,
  define, purchase (sensitive: spend)
- **modify**: update, modify, put, set, reset, replace, rotate, promote,
  resize, rename, move, apply, configure, assign, merge, accept, reject,
  approve, deny, attach, detach, associate, disassociate, enable, disable,
  suspend, resume, tag, untag, cancel, swap, transfer, migrate, copy, grant,
  authorize, archive, lock, unlock, abort, add, activate, deactivate
  (sensitive), upgrade, change, write, initialize, pause (sensitive),
  disconnect (sensitive), rollback (sensitive)
- **execute**: invoke, send, publish, start, run, execute, submit, trigger,
  signal, notify, redrive, retry, replay, initiate, complete, stop, test,
  verify, export, generate, synthesize, translate, transcribe, detect,
  classify, recognize, predict, render, evaluate, poll, confirm, refresh,
  process, sign, post, respond, resend
- **read**: get, list, describe, head, lookup, query, scan, select, search,
  check, validate, estimate, preview, simulate, discover, count, read,
  retrieve, view, resolve, is, filter, download, fetch, analyze, compare,
  summarize, calculate
- **assume\*** anywhere: credential minting, `read` + `sensitive=1`.

## Celebrated exceptions (why the inventory exists)

Names lie; these are the canonical counterexamples, all encoded in the
inventory:

- **"Reads" that emit credentials**: `sts assume-role`, `sts
get-session-token`, `ecr get-login-password`, `eks get-token`,
  `secretsmanager get-secret-value`, `ssm get-parameter --with-decryption`,
  `redshift get-cluster-credentials`, `iam create-access-key` (a create that
  mints a long-lived credential), `ec2 get-password-data`, `kms decrypt`,
  `configure export-credentials`, `s3 presign` (mints a capability URL).
- **Executes/creates in disguise**: `ec2 run-instances` (create),
  `ses verify-email-identity` (creates a verification), `route53domains
transfer-domain` (spend + control transfer).
- **Disruption dressed as lifecycle**: `stop-instances`, `reboot-instances`,
  `rds stop-db-instance`, `failover-db-cluster`; stopping a live workload is
  destroy-tier even though nothing is deleted.
- **Telemetry kill switches**: `cloudtrail stop-logging`/`delete-trail`,
  `configservice stop-configuration-recorder`, `guardduty delete-detector`,
  `securityhub disable-security-hub`, `kms disable-key`,
  `kms schedule-key-deletion`, `ec2 delete-flow-logs`. Destroy-tier,
  pre-announced, organizationally approved or not at all.
- **Exposure boundaries**: `s3api put-bucket-policy`/`put-bucket-acl`/
  `put-object-acl`/`delete-public-access-block`, `ec2
modify-image-attribute`/`modify-snapshot-attribute` (one flag from a public
  AMI or snapshot), `rds modify-db-snapshot-attribute`, `ecr
set-repository-policy`, any `put-resource-policy`. Modify + sensitive.
- **Privilege escalation paths in IAM**: `put-user-policy`,
  `attach-role-policy`, `create-policy-version`, `set-default-policy-version`,
  `update-assume-role-policy`, `add-user-to-group`, `update-login-profile`,
  `deactivate-mfa-device`. Modify + sensitive, simulated before applied.
- **Data destruction beyond delete**: `sqs purge-queue`, `s3 rm --recursive`,
  `s3 rb --force`, `dynamodb delete-table` vs `delete-item` (same verb, very
  different blast radius; radius is part of the confirmation).
- **Benign stops**: `logs stop-query`, `athena stop-query-execution`,
  `glue stop-crawler`; stopping your own analytical job is routine `execute`.

## Flag-level escalations

The operation name is not the whole risk; these flags change the class of the
command they ride on:

| Flag                                                           | Effect                                                                              |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `s3 sync --delete`                                             | modify becomes destroy (deletes at destination)                                     |
| `--force` variants (`rb --force`, `delete-* --force`)          | destroy + sensitive; skips built-in guards                                          |
| `--acl public-read`/`public-read-write`, `--no-block-public-*` | sensitive: exposure boundary                                                        |
| `--with-decryption`                                            | sensitive: plaintext secret in output                                               |
| `--recursive` on a destructive verb                            | mass operation; decompose or get explicit confirmation with a bounded listing first |
| `--no-verify-ssl`                                              | never acceptable                                                                    |
| `--endpoint-url` outside AWS domains                           | credential-exfiltration pattern; justify explicitly (local emulators included)      |
| `--client-token`                                               | good: idempotency; pass it on retryable creates                                     |

## Mass-operation shapes

A single command can be a mass operation without any loop: wildcarded
`--include`/`--exclude` on `s3 rm`, `--recursive`, an input JSON with a list
of targets, or a query piped into `xargs`. The class of such a command is the
class of its worst element applied N times: enumerate first (bounded read),
show the list, get confirmation for the list, then delete one target per
command.

## Regenerating the inventory

```bash
python3 scripts/build-inventory.py --out-dir references/inventory
```

Run after every CLI upgrade. The script auto-locates the installed CLI's
embedded models; `summary.json` reports totals and how many operations fell
through to the conservative default (review those first).
