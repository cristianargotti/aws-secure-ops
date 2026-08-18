# Changelog

All notable changes to the aws-secure-ops plugin are documented here.

## [2.2.0]

Dual-runtime release: the existing Claude Code plugin remains intact and the
same package is now installable as a Codex plugin.

### Codex

- Added the Codex manifest and repository marketplace metadata.
- Added a fail-closed read-only execution lane. Only known, non-sensitive,
  bounded reads through a policy-classified readonly profile and selected
  absolute AWS CLI path can run. Execute/create/modify/destroy, sensitive and
  configuration reads, unknown operations, custom endpoints, admin/frozen/
  personal profiles, and unbounded pagination are denied.
- Converted every upstream ask result to deny, because current Codex hook
  semantics do not safely pause an ask decision.
- Added exact profile/region/stamp/endpoint-isolation/non-interactive command
  requirements plus inherited and inline credential/context defenses.
- Added command-position discovery so documentation/search text is ignored,
  while wrappers, dynamic command names, loops, functions, control flow,
  prefix redirections, and obvious copied/symlinked CLI paths fail closed.
- Added a supervised hook launcher: classifier crashes, missing Python, or
  malformed output become valid deny output; SessionStart failures become a
  visible watchdog warning. The dispatcher ignores inherited shell functions,
  and policy/inventory/ledger special files cannot stall past the hook timeout.
- Added an offline Codex regression suite and Codex-aware doctor checks.

### Shared hardening

- Policy reads now use owner/mode/type checks and no-follow opens in the Codex
  lane.
- Ledger files are created mode 600 and reject symlinks, non-regular files,
  wrong owners, and hard-linked targets before append/chmod.
- Hooks dispatch by runtime from one hooks.json, preserving the Claude Code
  behavior and enabling the stricter Codex branch through PLUGIN_ROOT.
- Documentation now separates executable Claude mutations from Codex
  planning-only mutation guidance, documents hook trust, and states IAM
  read-only roles as the enforceable boundary.
- Active AWS CLI aliases are rejected in Codex because they can replace a
  command that otherwise passed classification.

### Inventory and bounded reads

- Marked plaintext or write-capable material sensitive, including generated
  passwords, decrypted WAF keys, Lambda code/configuration download data,
  presigned upload/download/SSO URLs, IPAM verification tokens, and WAF change
  tokens. These reads are denied in the Codex lane.
- Reclassified local SSO logout as destructive and sensitive.
- Codex denies `logs tail` and high-level `s3 ls`, which cannot enforce a total
  result bound, and directs callers to bounded `logs filter-log-events` and
  `s3api list-*` operations.

## [2.1.0]

Security-hardening pass on the gate, plus reproducible tooling. Driven by a deep
audit; every change ships with a pinned case in the new decision corpus.

### Gate

- **Spelling-robust escalations.** The public-ACL escalation matches `=`, quoted,
  and any-whitespace (including tab) forms, not just a single space; the public
  principal-grant check likewise.
- **Deeper construct coverage.** Process substitutions `<(...)`/`>(...)` and inline
  `bash -c`/`sh -c` script bodies (including here-strings and forms nested inside
  `$(...)`/backticks) are extracted and classified; a robust word splitter means a
  trailing comment with an unbalanced quote no longer makes extraction fail open.
- **Per-invocation loop scoping.** The mass-mutation deny is scoped to the actual
  loop body / dispatcher segment, removing the whole-command false positive that
  denied a single-target mutation whenever any loop text appeared anywhere.
- **Segment integrity.** Newlines and a single `&` are segment separators, so a
  later command can no longer inherit an earlier one's inline stamp or profile;
  a whitespace-only stamp is treated as absent.
- **Attribution.** Tool/automation markers are caught through NFKC + a scoped
  homoglyph fold (fullwidth and Cyrillic/Greek look-alikes), and are now also
  checked in a resource name the operator assigns on a create.
- **`frozen_accounts`** is enforced by the hook when an entry matches a resolved
  profile name; **`--recursive`/wildcard** deletes surface a mass-operation prompt.

### Inventory

- Telemetry-kill and spend/exposure operations (guardduty `update-detector`,
  cloudtrail `update-trail`, configservice `put-configuration-recorder`,
  securityhub `batch-disable-standards`, route53domains register/renew/transfer)
  are now `sensitive=1`; `logs tail` is a read (was a false-positive deny); plain
  `s3 sync` is no longer sensitive (only `sync --delete` escalates).
- **Reproducible pipeline.** The reviewed-corrections layer is committed as
  `corrections.json` and re-applied on rebuild, custom rows are overrides (no
  duplicate keys), and `summary.json` carries the keys the verifier reconciles, so
  a rebuild from the installed CLI reproduces the shipped inventory exactly.

### Tooling & packaging

- **`run-gate.sh`** resolves `python3`/`python`/`py` and fails closed where no
  interpreter exists, so the hook no longer fails open on a `python3`-less host.
- Preflight suggests the correct waiter for attach/register/update verbs (no more
  guaranteed hang); the ledger CLI parses `Z` timestamps and formats in UTC; the
  doctor and test suites no longer pollute the operator's real decision ledger.
- **Regression net.** A data-driven decision corpus (`run-corpus.py` +
  `corpus/decisions.jsonl`), a shell-launcher test, a version-consistency check
  (`release.py`), a property/differential fuzz over the corpus, and a CI workflow.

### Docs

- The threat model and skill no longer overstate coverage: the watchdog reconciles
  the inventory against its own summary (not the installed CLI), an unknown-service
  read-verb operation is honestly a residual, and the `frozen_accounts` contract is
  stated precisely.

## [2.0.0]

Repackaged as a standalone Claude Code plugin with a single enable/disable switch.

### Added

- **Plugin packaging** — gate, skill, and watchdog ship and toggle as one unit via
  a self-contained marketplace. The `PreToolUse` gate is wired through the plugin
  (`${CLAUDE_PLUGIN_ROOT}`) instead of a hand-edited `settings.json` entry.
- **Session watchdog** — a `SessionStart` health check (`aws-ops-doctor.py --quick`)
  that stays silent when healthy and warns via `systemMessage` if the seatbelt is
  loose (gate missing, policy invalid, inventory inconsistent with its summary).
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
