# aws-secure-ops (skill)

This is the **skill** component of the aws-secure-ops plugin -- the judgment
half of a universal protocol for operating the AWS CLI safely and accountably,
from a single describe to a production delete. The plugin bundles this skill
with the enforcement gate and a session watchdog, and the three travel and
toggle as one unit. For installation, the marketplace flow, and the on/off
switch, see the **repository README** one level up; this file describes what
lives inside the skill and how the pieces relate.

## What ships together

1. **The skill** (`SKILL.md` + `references/`) -- the operating loop: identity
   gate, least-privilege profiles, purpose stamping, staged mutations, tagging,
   waiters, secret hygiene, and audit-trail accountability. Plus a fully
   classified inventory of every operation in the installed CLI.
2. **The gate** (`scripts/classify-aws-command.py`) -- a `PreToolUse` hook that
   classifies every `aws` invocation against that inventory before it runs, and
   denies or pauses the risky ones. It is mechanical enforcement of the same
   taxonomy the skill teaches, and records each decision to a local,
   metadata-only ledger you can reconcile against CloudTrail. It has known
   limits; read `references/threat-model.md` before trusting it with anything.
3. **The watchdog** (`scripts/aws-ops-doctor.py --quick`) -- a `SessionStart`
   health check that stays silent when the seatbelt is sound and warns only if
   it has come loose (gate unregistered, policy invalid, inventory drift).
4. **The optional local policy** (`~/.claude/aws-ops.policy.json`) -- your
   org-specific facts (operator identity, profile classes, frozen accounts,
   required tags), kept private on your machine and never part of the shared
   package.

Because it is a plugin, gate + skill + watchdog enable and disable as one unit.
Disabling is a deliberate, total off; the hard controls for AWS remain where
they belong -- IAM, SCPs, permission boundaries, and read-only roles. The gate
lowers the odds of a careless keystroke; it does not replace them.

## The operating loop

- Confirm identity first: `aws sts get-caller-identity` against the profile you
  intend to use, before the first real call of any task.
- Classify the operation (read / execute / create / modify / destroy, plus a
  `sensitive` flag) and pick the lane it demands.
- Choose the least-privilege profile that works; switch to a privileged one
  only for the mutating commands themselves.
- Stamp every command with a purpose:
  `AWS_SDK_UA_APP_ID="<initials>-<task-slug>" aws ...` -- it lands in
  CloudTrail's userAgent, so the audit trail carries your intent.
- Mutate one target at a time, dry-run or change-set first when the service
  offers one, tag at creation, wait with waiters, verify with a read-back.
- Reconcile: every gate decision is recorded in a local ledger (metadata only)
  so you can check your session against CloudTrail via the purpose stamp.

## Installing outside the plugin

The plugin wires the gate and watchdog automatically -- see the repository
README. For an environment that runs the skill without the plugin system,
`scripts/aws-ops-install.py` registers (or, with `--uninstall`, removes) the
gate as a `PreToolUse` hook on the Bash tool; it is idempotent, backs up
`settings.json` first, and reverts only its own change. For best-effort
coverage of `aws` typed into an ordinary terminal, `scripts/aws-shim.sh` routes
those commands through the same classifier -- honestly best-effort, since a
path-qualified binary walks past it.

## Optional local policy

Create `~/.claude/aws-ops.policy.json` to bind the protocol to your
environment. The contract (shape only -- fill in your own facts):

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
    "team": "example-team",
    "owner": "corporate identity"
  },
  "notes": "free-form local rules"
}
```

The policy is binding when present; without it, the skill's conservative
defaults apply. Keep it out of any shared or version-controlled copy.

## Health check

```
python3 scripts/aws-ops-doctor.py
```

Runs entirely offline: verifies the gate compiles and is registered as a live
hook, the inventory is intact, the policy file (if any) is schema-sane, and the
seatbelt really denies an unstamped mutation while letting a pointed read
through. The `--quick` variant is what the session watchdog runs. Nonzero exit
means something needs fixing. To plan a single command before running it, use
`scripts/aws-preflight.py`.

## The promise

Attribution always names the accountable human operator -- in stamps, tags, and
resource names -- never the tooling that typed the command.
