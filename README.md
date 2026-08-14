# aws-secure-ops

A secure-by-default operating protocol for the **AWS CLI**, packaged as a
self-contained Claude Code plugin with a single on/off switch.

It bundles three things that travel and toggle together:

1. **The skill** — a universal protocol: identity gate, least-privilege profile
   selection, purpose stamping, pointed bounded queries, staged mutations with
   dry-run and change sets, professional tagging, single-target deletes, waiter-based
   timing, secret hygiene, and audit-trail accountability. Plus a fully classified
   inventory of every operation in the installed CLI.
2. **The gate** — an evasion-hardened `PreToolUse` hook that inspects every `aws`
   command _before_ it runs and returns allow / ask / deny. It records each decision
   to a local, metadata-only ledger you can reconcile against CloudTrail.
3. **The watchdog** — a `SessionStart` health check that warns you (and only then)
   if the seatbelt ever comes loose.

Every audit-visible value it produces — purpose stamps, tags, resource names —
attributes the action to the **accountable human operator, never the tooling**.

## Install

This repo is its own marketplace. Add it, install the plugin, and reload:

```
# From a local clone:
/plugin marketplace add /path/to/aws-secure-ops
# Or straight from GitHub once pushed:
/plugin marketplace add <your-handle>/aws-secure-ops

/plugin install aws-secure-ops@secure-ops
/reload-plugins
```

Non-interactive equivalents are available as `claude plugin marketplace add ...`,
`claude plugin install aws-secure-ops@secure-ops`, and `claude plugin enable ...`
(a restart applies newly added hooks).

## The toggle

Because it is a plugin, gate + skill + watchdog enable and disable as **one unit**:

```
/plugin disable aws-secure-ops@secure-ops   # gate, skill, and watchdog all off
/plugin enable  aws-secure-ops@secure-ops   # all back on
```

or in `settings.json` (`user`, `project`, or `local` scope):

```json
{ "enabledPlugins": { "aws-secure-ops@secure-ops": true } }
```

Disabling is a deliberate, total off. The hard controls for AWS remain where they
belong — IAM, SCPs, permission boundaries, and read-only roles; the gate lowers the
odds of a careless keystroke, it does not replace them. See the skill's
[`references/threat-model.md`](plugins/aws-secure-ops/skills/aws-secure-ops/references/threat-model.md)
for exactly what the gate catches and what it cannot.

## Optional: a local policy file

Drop a private `~/.claude/aws-ops.policy.json` to declare your own profile classes
(read-only / admin / frozen / personal), required tags, and operator stamp prefix.
It is read at runtime and **never ships with the plugin**. Without it, the gate runs
on conservative defaults. The contract is documented in the skill's `SKILL.md`.

## Optional: terminal coverage

The gate covers `aws` commands run inside Claude Code. To extend the same checks to
your normal terminal, opt into the best-effort shell wrapper:

```
source /path/to/aws-secure-ops/plugins/aws-secure-ops/skills/aws-secure-ops/scripts/aws-shim.sh
```

It is honest about its limits — a path-qualified `/usr/bin/aws` bypasses it — so it is
a net against carelessness, not a substitute for IAM.

## Without the plugin system

If you do not use Claude Code plugins, install the same skill and hook directly:

```
claude plugin marketplace add /path/to/aws-secure-ops   # simplest, or:
python3 plugins/aws-secure-ops/skills/aws-secure-ops/scripts/aws-ops-install.py
```

`aws-ops-install.py` wires the `PreToolUse` hook into your `settings.json` (with a
backup, preserving your other hooks), scaffolds a policy file, and runs the doctor.
`--uninstall` removes only what it added.

## Health check

```
python3 plugins/aws-secure-ops/skills/aws-secure-ops/scripts/aws-ops-doctor.py
```

Verifies the gate compiles, the hook is wired, the policy is valid, the inventory is
consistent, and the seatbelt actually denies an unstamped mutation.

## Before you publish

This repo ships with placeholder identity fields. Set them to yours before pushing:

- `.claude-plugin/marketplace.json` → `owner`
- `plugins/aws-secure-ops/.claude-plugin/plugin.json` → `author`, and add
  `homepage` / `repository` once the GitHub repo exists
- `LICENSE` → copyright holder (or swap the license entirely)

The skill content itself is deliberately organization-agnostic: no account IDs, no
internal system names. Keep it that way.
