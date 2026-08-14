# The mutation ladder

Every create, modify, or destroy climbs the same ladder. Skipping a rung is
how "we tried something in production and rolled back" happens; a rollback in
a shared environment reads as "we acted at random", and the cost of the rungs
is minutes.

```
1 feasibility (read-only)  ->  2 rehearse (dry run / change set / simulate)
        -> 3 explain and confirm -> 4 execute (one target) -> 5 wait -> 6 verify -> 7 evidence
```

## 1. Feasibility, read-only

Prove the operation CAN succeed before asking AWS to do it. A change set or a
syntactically valid command proves the request is well-formed, not that the
underlying operation is possible.

- Does the target exist, and is it what you think? `describe`/`get` it, read
  its tags, check its state.
- Who owns the resource model? Managed and requester-owned resources
  (service-managed endpoints, service-linked roles, managed master passwords)
  reject operations that look perfectly valid. Check `Owner` fields and
  authorization state (`describe-*-authorization`, sharing attributes) first.
- Are dependencies satisfied (subnets, security groups, capacity, quotas)?
  `aws service-quotas get-service-quota` beats discovering a limit mid-change.
- Will anything collide (name uniqueness, CIDR overlaps, existing listeners)?

## 2. Rehearse

Use the strongest rehearsal the service offers, in this order:

- **`--dry-run`** (EC2 family and others; the inventory's `dryrun` column says
  which operations support it). Expect `DryRunOperation` on success;
  `UnauthorizedOperation` means the authorization itself would fail.
- **Change sets** for CloudFormation, always, never a blind direct update:

  ```bash
  aws cloudformation create-change-set --stack-name <s> --change-set-name <c> \
    --template-body file://t.yml --parameters file://params.json --tags ...
  aws cloudformation wait change-set-create-complete --stack-name <s> --change-set-name <c>
  aws cloudformation describe-change-set --stack-name <s> --change-set-name <c>
  # READ the changes: Action, Replacement=True|Conditional, Scope. Replacement
  # on a stateful resource is a destroy in costume.
  aws cloudformation execute-change-set --stack-name <s> --change-set-name <c>
  aws cloudformation wait stack-update-complete --stack-name <s>
  ```

  Pass parameter lists via `file://params.json`; repeated `Key=,Value=` pairs
  on the command line collide in some shells and CLI versions, and `file://`
  does not expand when nested inside list-typed parameter values, so keep the
  whole list in the file.

- **IAM policy simulation** before attaching or changing policies:
  `aws iam simulate-custom-policy` / `simulate-principal-policy`. Note the
  simulator caps each document in `policy-input-list` around 2000 characters;
  split allow and deny statements into separate documents with identical
  semantics. Simulation is a pure dry run: it never produces real denials, so
  the first live call is still part of verification.
- **`--generate-cli-skeleton` + `--cli-input-json`** for complex inputs:
  generate, fill, review the JSON as an artifact, then run. The reviewed input
  file is part of the evidence.

## 3. Explain and confirm

One plain sentence before the command: what changes, why, and under what
authorization. Destructive or sensitive operations (the inventory's `destroy`
class and `sensitive` flag) additionally require explicit human confirmation,
regardless of how sure you are. If the sentence is hard to write, the change
is not understood yet.

## 4. Execute, one target per command

- Exactly one resource per mutating command. Never `for`/`while`/`xargs` over
  a destructive verb; a loop turns one mistake into a mass event.
- Purpose stamp inline (`AWS_SDK_UA_APP_ID="..."`), explicit `--profile`,
  explicit `--region`.
- Tags at creation time (see `tagging.md`).
- If the command supports idempotency tokens (`--client-token`), pass one so a
  retry cannot double-create.

## 5. Wait

Use the matching waiter or a bounded poll (`waiters-and-timing.md`). Do not
issue the next dependent command on hope; half-completed chains are how
inconsistent states are born.

## 6. Verify with a read-back

Exit code zero means the control plane accepted the request. Verification
means a read proves the intended state: `describe` the resource and check the
actual field you meant to change, hit the endpoint, read the metric. For
deletions, verify absence, and verify nothing adjacent changed.

## 7. Evidence

Close the loop in your worklog: the command, the verification output, and for
notable changes a pointed audit-trail confirmation:

```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=<Operation> --max-items 3
```

The record should read exactly like your stated intent. If it would not, the
gap is the finding.

## Failure handling

- A failed mutation is reported with the exact error, not retried blind.
  `AccessDenied` is a finding about authorization design; throttling is a
  pacing signal; a rollback is a feasibility rung that was skipped.
- Know the undo BEFORE the do: the reverse command, the snapshot to restore,
  or the explicit acceptance that the change is one-way. One-way changes get
  the strictest confirmation.
