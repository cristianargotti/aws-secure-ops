# Changelog

All notable changes to the aws-secure-ops package are documented here.

## [2.0.0]

Repackaged as a standalone, togglable Claude Code plugin.

### Added

- **Plugin packaging**: the gate, this skill, and a session watchdog ship and
  toggle as one unit. The `PreToolUse` gate is wired through the plugin instead
  of a hand-edited `settings.json` entry; disabling is a deliberate, total off,
  with the hard controls (IAM, SCPs, permission boundaries, read-only roles)
  unchanged underneath.
- **Session watchdog** (`scripts/aws-ops-doctor.py --quick`): a `SessionStart`
  health check that stays silent when the seatbelt is sound and warns only when
  it has come loose (gate unregistered, policy invalid, inventory drift versus
  the installed CLI). It warns; it never blocks.
- **Terminal shim** (`scripts/aws-shim.sh`): opt-in, best-effort routing of
  ordinary-terminal `aws` commands through the same classifier. A path-qualified
  binary bypasses it -- documented as such in `references/threat-model.md`.
- **Installer** (`scripts/aws-ops-install.py`): wires or removes the gate hook
  for environments running the skill outside the plugin -- idempotent, backs up
  `settings.json`, and `--uninstall` reverts only its own change.
- **Ledger rotation** (`scripts/aws-ops-ledger.py rotate`): the decision ledger
  rotates by size and age instead of growing without bound.
- **Policy lint** in the doctor: flags misleading profile names and common
  policy-file mistakes.
- **Living evasion corpus**: a security regression suite that grows with every
  discovered bypass.
- **Portability**: runs on macOS and Linux; interpreter discovery instead of a
  hardcoded path, and no BSD-only flags.

### Changed

- `SKILL.md`: a "Packaging and toggle" section covering the plugin unit, the
  watchdog, the terminal shim and its honest limit, and ledger rotation;
  tooling pointers extended to the shim and installer. All existing guidance and
  hard prohibitions unchanged.
- `references/threat-model.md`: the shim added to the out-of-CLI coverage
  discussion (best-effort, bypassable), and the watchdog plus the explicit,
  total plugin toggle added to the defense-in-depth account. Every prior claim
  preserved.
- `README.md`: reframed as the skill inside the plugin, with install pointing to
  the repository README and a non-plugin path via the installer and shim.

## [1.1.0]

Hardening pass.

### Added

- **Evasion hardening** in the enforcement gate: better detection of commands
  that try to slip past classification (wrappers, quoting tricks, indirect
  invocation patterns).
- **Local decision ledger**: the gate records every allow/ask/deny decision
  locally (metadata only, no secrets), enabling session-level reconciliation
  against CloudTrail via the purpose stamp. New reference:
  `references/ledger-and-reconciliation.md`.
- **Preflight tool** (`scripts/aws-preflight.py`): an offline planning card
  for an intended command -- classification, policy check, suggested stamp,
  required tags, matching waiter, and a proposed verification read-back.
- **Doctor tool** (`scripts/aws-ops-doctor.py`): an offline installation
  self-test that verifies the gate, inventory, hook registration, policy
  schema, and the deny/allow behavior of the seatbelt.
- **Threat model** (`references/threat-model.md`): an honest statement of
  what the gate does and does not catch, including ambient credentials and
  file-sourced payloads.
- **Incident and break-glass reference**
  (`references/incident-and-breakglass.md`): operating under pressure without
  abandoning the protocol.
- **Multi-account and regions reference**
  (`references/multi-account-and-regions.md`): profile discipline, region
  pinning, and cross-account boundaries.
- **Cost and commitment reference** (`references/cost-and-commitment.md`):
  guardrails for operations with spend or commitment consequences.
- Package docs: `README.md` quickstart, this changelog, and a `VERSION` file.

### Changed

- `SKILL.md`: reference map extended with the new references; pointers added
  to the decision ledger, the threat model, and the preflight/doctor tooling.
  All existing guidance and hard prohibitions unchanged.

## [1.0.0]

Initial shareable package: the secure-operations skill, the full classified
CLI inventory, the PreToolUse enforcement gate, per-domain service
references, and the optional local policy contract.
