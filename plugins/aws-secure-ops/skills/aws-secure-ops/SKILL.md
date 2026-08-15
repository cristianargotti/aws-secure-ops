---
name: aws-secure-ops
description: ALWAYS invoke before running ANY aws CLI command or planning ANY AWS operation, in every account and every environment. This covers reads, log queries, deploys, creates, modifications, deletions, SSM sessions, and credential handling alike, even a single innocuous-looking describe. Enforces a universal secure-operations protocol, identity gate, least-privilege profile selection, purpose stamping, pointed bounded queries, staged mutations with dry-run and change sets, professional tagging, single-target deletes, waiter-based timing, secret hygiene, and audit-trail accountability. Consult it again before anything destructive.
---

# AWS secure operations

Every AWS API call is an audit statement. CloudTrail records who you were, which
role you used, where you came from, what you asked for, and the user agent that
asked. Organizations increasingly run automated analysis over these trails, and
a reviewer, human or automated, will read your session as a narrative. This
skill exists so that the narrative is always the same one: a named operator,
using the least privilege that works, doing documented work, one deliberate
step at a time.

Three ideas carry everything else:

1. **Least privilege is visible.** The role you use is stamped on every event.
   A session of reads under a read-only role is a non-event; the same reads
   under an administrator role invite questions. Privilege you do not carry
   cannot be misused, misread, or stolen mid-session.
2. **Intent must travel with the action.** A resource with a clear purpose tag
   and an event stream carrying a purpose stamp explains itself. Anything that
   needs you present to explain it is under-documented.
3. **Blast radius is a choice made before the command.** Dry runs, change
   sets, single-target commands, and look-before-delete are how you choose a
   small one.

Attribution names the accountable human operator, never the tooling that typed
the command. The IAM principal already identifies the session; what you sign
in tags, stamps, and names is human responsibility.

## The operating loop

Run this loop for every task that touches AWS. Steps 0 to 3 take seconds and
are never skipped, not even for "just one describe".

### 0. Load the local policy, if present

If `~/.claude/aws-ops.policy.json` exists, its rules are binding: profile
classes (read-only, admin, frozen, personal), required tags, and the operator
identity. Without it, operate with the conservative defaults in this skill.
The policy contract is at the bottom of this file.

### 1. Identity gate

Confirm who you are before the first call of a task:

```
AWS_SDK_UA_APP_ID="<stamp>" aws sts get-caller-identity --profile <profile>
```

Check the account ID and the assumed role against your intent. Never operate on
an implicit profile or inherited environment credentials; name the profile
explicitly on every command. Never trust a profile's _name_, profiles named
"readonly" have been found carrying administrator roles; trust only the role
that `get-caller-identity` returns.

### 2. Classify the operation

Every CLI operation falls in one class, and the class decides the lane:

| Class     | Meaning                                                  | Lane                                         |
| --------- | -------------------------------------------------------- | -------------------------------------------- |
| `read`    | No state change, no credential material                  | Proceed, pointed and bounded                 |
| `execute` | Side effect without infra CRUD (invoke, send, start job) | Purpose stamp required                       |
| `create`  | Provisions a resource                                    | Stamp + tags + mutation ladder               |
| `modify`  | Changes existing resource or config                      | Stamp + mutation ladder                      |
| `destroy` | Removes, terminates, or disrupts                         | Stamp + ladder + explicit human confirmation |

The orthogonal `sensitive` flag (credential material, trust or exposure
boundary changes, spend commitments, workload disruption) forces explicit human
confirmation regardless of class.

Look the operation up in the full inventory (every operation of the installed
CLI, classified):

```
grep -m1 "^ec2,delete-volume," references/inventory/inventory.csv
# service,operation,class,sensitive,dryrun,paginated,source,rule
```

If the operation is not in the inventory (newer CLI), apply the verb taxonomy
in `references/operation-classes.md`, and treat an unknown verb as a guarded
mutation until proven otherwise.

### 3. Choose the least-privilege profile

- Reads: use a read-only profile when one exists for the account. The entire
  session reads differently in the audit trail when the role itself cannot
  mutate.
- Mutations: switch to the privileged profile only for the commands that mutate,
  then drop back to read-only for verification reads where practical.
- Frozen accounts (policy file): reads only, forever, no exceptions in-band.
  Unfreezing is an organizational decision, not an operational one.
- Accounts owned by other teams: pointed reads only; mutations only on the
  owner's explicit request.

### 4. Stamp the purpose

Prefix every command, reads included, with an inline purpose stamp:

```
AWS_SDK_UA_APP_ID="<operator-initials>-<task-slug>" aws ...
```

The stamp lands in the `userAgent` field of every CloudTrail event (as
`app/<stamp>`), so the audit trail carries your intent even for operations that
take no tags. Rules: kebab-case, 50 characters or fewer (the AWS SDK app-id
limit the enforcement hook also applies), names the real task
(`xx-storage-lifecycle-fix`, not `xx-stuff`), operator initials first, and
never a tool or automation name. Shell state does not persist between separate
command invocations in most execution harnesses, so the stamp goes inline on
each command, not in an exported variable you hope survives.

### 5. Run the lane

**READ lane.** Pointed and bounded, never sweeping. Filter server side, cap
page counts, name the exact resource. One line of stated purpose per block of
related reads. Bursts of rapid-fire calls from a human identity read as
compromised automation. Full patterns: `references/querying-and-logs.md`.

**EXECUTE lane.** State what the invocation will cause and where its output
lands before running it. Bounded inputs, verified outputs.

**CREATE / MODIFY lane.** Follow the mutation ladder,
`references/mutation-ladder.md`: read-only feasibility first, dry run or change
set when the service offers one, state what and why, one target per command,
wait correctly, verify with a read-back. Tag every taggable resource at
creation time per `references/tagging.md`; the purpose tag is written so that
an auditor reads documented, authorized work.

**DELETE lane.** Look before you delete: describe the target, read its tags,
confirm it is yours and it is what you believe it is. One deletion per
command. Never loop a destructive command over a list; if several resources
must go, each gets its own explained, confirmed command. Verify the resource
is gone and nothing else changed. Never chain rapid create-and-delete cycles;
they read as churn or cover-up. Spacing between deliberate actions is free;
suspicion is not.

**SECRET lane.** Secret material never lands in a transcript, a log, a chat,
or a document. Retrieve secrets only into the consuming process (pipe them
directly), check for existence and metadata with list/describe instead of
value reads, and remember that remote-command text (for example Systems
Manager send-command) is recorded verbatim in command history and the audit
trail: parameterize on the remote side, never inline a secret in command text.

### 6. Wait correctly

Use the service's waiter when one exists (`aws <svc> wait <waiter>`); the full
waiter map with expected timings is `references/inventory/waiters.csv`. When no
waiter exists, poll with a bounded loop: generous sleeps, a hard attempt cap,
never a tight loop. Tight polling hammers the API, trips throttling, and fills
the audit trail with noise. Eventual consistency is real (IAM propagation, DNS,
distribution deploys); patience is part of correctness. Details:
`references/waiters-and-timing.md`.

### 7. Verify and account

A mutation is not done when the command exits zero; it is done when a read-back
proves the intended state. After notable changes, a pointed
`aws cloudtrail lookup-events --max-items 5` confirms the record says what you
meant it to say. If an audit process, human or automated, later asks about your
session, a short professional explanation is part of the job, not an
imposition; a well-run session makes that explanation a single sentence.

Accounting also happens locally: every gate decision -- allow, ask, or deny --
is recorded in a local decision ledger (metadata only, never secrets or
payloads), so at the end of a session you can reconcile your own record
against CloudTrail through the purpose stamp: the ledger tells you which
stamps and time windows to look up, and the trail confirms they landed. How
to read and reconcile it: `references/ledger-and-reconciliation.md`.

## Session shape

- **One intent per session.** A session is analyzed as a narrative; keep it
  coherent. Unrelated work belongs in a separate session with its own stamp.
- **No bursts, no mass operations.** Batch READS legitimately by passing
  multiple IDs to a single describe call. Never batch mutations; one target
  per mutating command, always.
- **Tests are announced, labeled, and cleaned.** Temporary resources carry a
  `TEST-` name prefix, full tags including an expiry, and a purpose tag that
  states the test and its cleanup plan. Announce controlled tests to the
  owning team before running them, and verify cleanup left zero residue.
- **Explain before, not after.** Before any mutating command, one plain
  sentence: what it changes and why. If you cannot write that sentence, you
  are not ready to run the command.

## Hard prohibitions

These hold in every account, every environment, and no task requirement
overrides them in-band:

1. Never disable or degrade audit and security telemetry (trails, recorders,
   detectors, loggers) without explicit organizational approval. Class
   `destroy`, always confirmed, always pre-announced.
2. Never widen an exposure boundary (public ACLs, resource policies opened to
   the world, public sharing attributes on images/snapshots) without explicit
   approval. These are one-command data breaches.
3. Never print credential or secret material into a transcript, log, or
   document. `--no-verify-ssl` is never acceptable. A custom `--endpoint-url`
   outside AWS is a credential-exfiltration pattern; question it every time.
4. Never mutate a frozen account.
5. Never loop or template a destructive command over a list of targets.
6. Never place secrets in remote-command text; history and trails record it.
7. Never let a tool or automation name into stamps, tags, resource names, or
   any audit-visible value. Attribution is the operator's.
8. Never work around a denied or failing authorization by switching
   credentials mid-task without stating why; an authorization failure is a
   finding to report, not an obstacle to route around.

## Local policy contract

`~/.claude/aws-ops.policy.json`, optional, binding when present, and never
part of a shared copy of this skill:

```json
{
  "operator": { "name": "corporate identity", "stamp_prefix": "xx" },
  "profiles": {
    "prod-read": "readonly",
    "prod-admin": "admin",
    "legacy-frozen": "frozen",
    "personal-lab": "personal"
  },
  "frozen_accounts": ["111111111111"],
  "required_tags": {
    "environment": "production",
    "team": "team-name",
    "owner": "corporate identity"
  },
  "notes": "free-form local rules"
}
```

Semantics: `readonly` profiles are the default for reads; `admin` profiles are
used only during mutating commands; a `frozen` profile accepts reads only (the
enforcement hook denies every mutation on it); `personal` profiles are outside
this protocol's account rules but still get its hygiene. `required_tags` are
merged into every tagging operation. `frozen_accounts` entries are honored by
the hook only when they match a resolved profile _name_ (the gate cannot map a
profile to an account ID without calling AWS); an account-ID entry is advisory
— the doctor lints it, but a real account freeze must live in a deny SCP and in
the credential lifecycle, never only here.

## Reference map

| Open                                      | When                                                                                                                                                                                                        |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `references/operation-classes.md`         | Classifying an operation the inventory does not settle; flag-level escalations (`--force`, `sync --delete`, public ACLs)                                                                                    |
| `references/querying-and-logs.md`         | Any read work: filters, pagination, CloudWatch Logs, Logs Insights, CloudTrail lookups, log hygiene                                                                                                         |
| `references/mutation-ladder.md`           | Any create/modify/destroy: feasibility, dry runs, change sets, verification, evidence                                                                                                                       |
| `references/tagging.md`                   | Creating anything taggable; writing purpose tags; per-service tag syntax                                                                                                                                    |
| `references/waiters-and-timing.md`        | Waiting on any change: waiters, bounded polling, eventual consistency, CLI timeouts and retries                                                                                                             |
| `references/services/<domain>.md`         | Deep per-domain patterns and destructive traps (compute, storage, identity-security, networking, databases, observability, messaging-integration, deploy-iac, containers, data-analytics-ai, platform-misc) |
| `references/inventory/`                   | The full classified operation map of the installed CLI, plus waiters; regenerate with `scripts/build-inventory.py` after a CLI upgrade                                                                      |
| `references/threat-model.md`              | Understanding what the enforcement gate does and does not catch; its known limits and the judgment that must fill them                                                                                      |
| `references/incident-and-breakglass.md`   | Operating under incident pressure: break-glass access, urgency without shortcuts, and cleaning up after the emergency                                                                                       |
| `references/multi-account-and-regions.md` | Working across several accounts or regions: profile discipline, region pinning, and cross-account read/mutate boundaries                                                                                    |
| `references/cost-and-commitment.md`       | Operations with spend or commitment consequences: purchases, capacity reservations, budget guardrails                                                                                                       |
| `references/ledger-and-reconciliation.md` | Reading the local decision ledger and reconciling a session against CloudTrail via the purpose stamp                                                                                                        |

The enforcement hook, `scripts/classify-aws-command.py`, applies the same
taxonomy mechanically before any command runs; the skill is the judgment, the
hook is the seatbelt. And like any seatbelt, it has known limits -- it cannot
see ambient credentials or payloads sourced from files, among other gaps --
so read `references/threat-model.md` to know what it does not catch.

## Packaging and toggle

This skill ships inside a togglable Claude Code plugin: the gate (a
`PreToolUse` hook), this skill, and a `SessionStart` watchdog enable and
disable as one unit. Disabling is a deliberate, total off -- there is no
partial state -- and it changes nothing about the hard controls, which live
where they belong: IAM, SCPs, permission boundaries, and read-only roles. The
gate only lowers the odds of a careless keystroke; it never replaces them.

The **watchdog** (`scripts/aws-ops-doctor.py --quick`) runs once at session
start and stays silent when the seatbelt is sound. It speaks only to warn --
gate missing, policy invalid, inventory inconsistent with its own summary -- so
a control that quietly stopped working announces itself instead of failing in
silence. (Drift against the _installed_ CLI is not auto-detected: re-run
`scripts/build-inventory.py` + `scripts/verify-inventory.py` after a CLI
upgrade.)

Tooling: `scripts/aws-preflight.py` prints a planning card for a command
before you run it; `scripts/aws-ops-doctor.py` verifies the installation is
healthy; `scripts/aws-ops-install.py` wires (or removes) the gate hook for
environments that run it outside the plugin. `scripts/aws-shim.sh` is an
opt-in shim that routes ordinary-terminal `aws` commands through the same
classifier -- best-effort terminal coverage, not a boundary: a path-qualified
binary (`/usr/bin/aws`) sidesteps it, so it complements the IAM- and SCP-level
controls rather than standing in for them. The decision ledger rotates by size
and age (`scripts/aws-ops-ledger.py rotate`), so a long-lived install keeps
recent history without growing without bound.
