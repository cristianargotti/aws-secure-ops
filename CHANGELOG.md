# Changelog

All notable changes to the aws-secure-ops plugin are documented here.

## [2.0.0]

Repackaged as a standalone Claude Code plugin with a single enable/disable switch.

### Added

- **Plugin packaging** — gate, skill, and watchdog ship and toggle as one unit via
  a self-contained marketplace. The `PreToolUse` gate is wired through the plugin
  (`${CLAUDE_PLUGIN_ROOT}`) instead of a hand-edited `settings.json` entry.
- **Session watchdog** — a `SessionStart` health check (`aws-ops-doctor.py --quick`)
  that stays silent when healthy and warns via `systemMessage` if the seatbelt is
  loose (gate missing, policy invalid, inventory drift versus the installed CLI).
- **Opt-in terminal shim** — `aws-shim.sh` routes normal-terminal `aws` commands
  through the same classifier (best-effort; a path-qualified binary bypasses it).
- **Installer** — `aws-ops-install.py` wires/removes the hook for non-plugin users
  (idempotent, backs up `settings.json`, `--uninstall` reverts only its own change).
- **Ledger rotation** — the decision ledger rotates by size/date instead of growing
  without bound.
- **Living evasion corpus** — `test-evasion-corpus.sh`, the security regression suite
  that grows with every discovered bypass.
- **Policy lint** — the doctor flags misleading profile names and policy mistakes.
- Linux portability and a measured (not speculative) inventory-lookup path.

### Changed

- Distribution is now plugin-first; the `.skill` archive plus `aws-ops-install.py`
  remains as a fallback channel for environments without the plugin system.

## [1.1.0]

Evasion-hardening pass on the enforcement gate.

### Added

- Closed path-qualified invocation, command-substitution nesting, cross-segment
  profile carry, `find -exec` / `parallel` mass-mutation, public-principal grants,
  file-sourced policy bodies, and separator/invisible-character marker obfuscation.
- Local decision ledger (metadata only), operator tooling (`aws-preflight.py`,
  `aws-ops-doctor.py`, `aws-ops-ledger.py`, `verify-inventory.py`), an honest
  threat model, and break-glass / multi-account / cost references.

## [1.0.0]

Initial universal secure-AWS-CLI protocol: skill, fully classified operation
inventory, and the `PreToolUse` enforcement gate.
