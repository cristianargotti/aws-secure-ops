# AWS Secure Ops plugin

This package supports Claude Code and Codex from the same source tree.

| Runtime | Enforcement |
| --- | --- |
| Claude Code | Existing allow / ask / deny protocol, including staged mutations. |
| Codex | Fail-closed, read-only AWS CLI lane. Mutations and sensitive reads are blocked and may only be planned or reviewed. |

## Codex contract

Codex does not safely pause a `PreToolUse` decision of `ask`, so this package
converts every such result to `deny`. A permitted read must use:

- a profile classified `readonly` in `~/.claude/aws-ops.policy.json`;
- the selected absolute AWS CLI path;
- an explicit region, `--no-cli-pager`, and `--no-cli-auto-prompt`;
- inline `AWS_SDK_UA_APP_ID=<operator-task>` and
  `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true`;
- equal `--max-items` and `--page-size` values from 1 through 100 when the
  pinned inventory marks the operation paginated.

The policy must be a user-owned regular file with mode 600. The Codex decision
ledger is metadata-only and is stored at
`~/.codex/aws-secure-ops-ledger.jsonl` with mode 600.
Inherited CA/proxy variables require an exact private-policy
`allowed_environment` entry. Other inherited `AWS_*`, Python, loader, or TLS
key-log overrides are denied. Interactive PTY commands are also denied because
later `write_stdin` input is not checked by a second PreToolUse event.
Active AWS CLI aliases are denied because they can replace a permitted command.
Codex also blocks debug output, interactive auto-prompt, unbounded timeouts,
`s3 ls`, and `logs tail`; use bounded `s3api list-*` or
`logs filter-log-events` reads instead.

## Validation

All bundled tests are offline and never invoke AWS:

```sh
python3 skills/aws-secure-ops/scripts/test-codex-readonly.py
bash skills/aws-secure-ops/scripts/test-run-gate.sh
```

Run the doctor with the environment used by the Codex hook:

```sh
AWS_OPS_HOOK_RUNTIME=codex AWS_OPS_MODE=readonly \
PLUGIN_ROOT="$PWD" \
python3 skills/aws-secure-ops/scripts/aws-ops-doctor.py --quick
```

Codex hooks are not trusted automatically when a plugin is installed. Review
the two `aws-secure-ops` hooks individually through `/hooks` after each update,
then verify them from a new task.

## Security boundary

The hook is a seatbelt for direct AWS CLI use, not a sandbox. Keep every
credential exposed to Codex genuinely read-only and retain IAM, SCPs,
permission boundaries, and CloudTrail as the enforceable controls. The Codex
lane currently targets macOS/Linux shell runtimes with Python 3.8 or newer.
