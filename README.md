# aws-secure-ops

Secure-by-default AWS CLI operating guardrails packaged for both Claude Code
and Codex from one repository.

| Runtime | Effective execution policy |
| --- | --- |
| Claude Code | Existing upstream allow / ask / deny protocol, including staged and confirmed mutations. |
| Codex | Fail-closed read-only lane: explicit, bounded, non-sensitive reads only. Mutations are planned or reviewed, never executed. |

Codex does not currently pause safely when a `PreToolUse` hook returns `ask`.
The Codex branch therefore converts every `ask` result to `deny`; this is an
intentional safety boundary, not a missing confirmation dialog.

## What ships

1. **Skill** — identity gate, least privilege, purpose stamping, bounded
   queries, mutation planning, tagging, timing, secret hygiene, and
   accountability.
2. **Gate** — an evasion-hardened `PreToolUse` classifier with a pinned
   inventory of 17,806 AWS CLI operations.
3. **Watchdog** — an offline `SessionStart` doctor that stays silent when
   healthy and warns when the seatbelt is loose.
4. **Ledger** — metadata-only local decisions, never raw command text,
   payloads, credentials, or secret values.

## Install in Claude Code

```text
# From a local clone:
/plugin marketplace add /path/to/aws-secure-ops

# Or from GitHub:
/plugin marketplace add cristianargotti/aws-secure-ops

/plugin install aws-secure-ops@secure-ops
/reload-plugins
```

Non-interactive equivalents are available through `claude plugin marketplace
add`, `claude plugin install`, and `claude plugin enable`.

## Install in Codex

```sh
# From a local clone:
codex plugin marketplace add /path/to/aws-secure-ops

# Or from GitHub:
codex plugin marketplace add cristianargotti/aws-secure-ops

codex plugin add aws-secure-ops@secure-ops
```

Installation does not automatically trust hooks. After the final install or
update:

1. Open a new Codex task and run `/hooks`.
2. Choose **Review hooks**; do not choose **Trust all**.
3. Review and trust only the `PreToolUse` and `SessionStart` hooks belonging
   to `aws-secure-ops@secure-ops`.
4. Start another new task and run the offline doctor/canary described below.

Hook trust is tied to the exact definition hash, so every hook change requires
review again. For a Git marketplace update, refresh the marketplace snapshot
before reinstalling:

```sh
codex plugin marketplace upgrade secure-ops
codex plugin remove aws-secure-ops@secure-ops
codex plugin add aws-secure-ops@secure-ops
```

For a local-path marketplace, update the clone first (for example, `git pull`),
then run the same remove/add pair. In both cases, start a new task and review
the two new hook hashes through `/hooks`.

Do not keep a second personal copy enabled at the same time; duplicated
`PreToolUse` hooks create ambiguous behavior.

## Private policy

The plugin reads `~/.claude/aws-ops.policy.json`; it never ships this private
file. Example:

```json
{
  "operator": { "name": "corporate identity", "stamp_prefix": "xx" },
  "profiles": {
    "prod-read": "readonly",
    "prod-admin": "admin",
    "legacy-frozen": "frozen",
    "personal-lab": "personal"
  },
  "frozen_accounts": ["legacy-frozen"],
  "required_tags": {
    "environment": "production",
    "team": "team-name",
    "owner": "corporate identity"
  },
  "allowed_environment": {
    "SSL_CERT_FILE": "/absolute/path/to/corporate-ca.pem"
  },
  "ledger": true
}
```

Claude treats the policy as optional. Codex requires a user-owned regular file
with mode 600 and permits only profiles classified `readonly`. Inherited CA or
proxy variables are rejected unless the private policy lists the exact key and
value under `allowed_environment`; Python, loader, credential, profile, region,
and endpoint overrides can never be allowlisted.

## Codex command contract

The gate chooses the first installed executable from the known absolute paths
`/opt/homebrew/bin/aws`, `/usr/local/bin/aws`, and `/usr/bin/aws`. A permitted
read has this shape:

```sh
AWS_SDK_UA_APP_ID="<operator-prefix>-<task-slug>" \
AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true \
/absolute/path/to/aws sts get-caller-identity \
  --profile <readonly-profile> \
  --region <region> \
  --no-cli-pager \
  --no-cli-auto-prompt
```

For operations marked paginated, add equal `--max-items` and `--page-size`
values from 1 through 100. The gate blocks implicit/admin/frozen/personal
profiles, unknown operations, sensitive/configuration reads, custom endpoints,
credential/context overrides, AWS CLI aliases, interactive prompts and PTYs,
debug output, unbounded/zero timeouts, wrappers, loops, and every mutating
class. High-level `s3 ls` and `logs tail` are denied in Codex because neither
offers a reliable total-result bound; use bounded `s3api list-*` or
`logs filter-log-events` operations instead.

## Offline validation

These commands classify synthetic hook events only; they never invoke AWS:

```sh
cd plugins/aws-secure-ops/skills/aws-secure-ops/scripts
python3 test-codex-readonly.py
bash test-run-gate.sh
python3 aws-ops-doctor.py --quick
```

For the Codex packaging checks, run:

```sh
AWS_OPS_HOOK_RUNTIME=codex \
AWS_OPS_MODE=readonly \
PLUGIN_ROOT="$(cd ../../.. && pwd)" \
python3 aws-ops-doctor.py --quick
```

A safe end-to-end hook canary after trust uses a path that cannot exist:

```sh
/definitely-not-real/aws sts get-caller-identity
```

An active hook denies it before the shell. Without the hook it can only fail
with file-not-found; in neither case can it contact AWS.

## Optional Claude/terminal compatibility

`aws-ops-install.py` wires the legacy Claude settings hook when the plugin
system is unavailable. `aws-shim.sh` provides best-effort terminal coverage.
Neither is a Codex escape hatch.

## Security boundary

The hook is a safety belt, not a sandbox. IAM read-only roles, SCPs, permission
boundaries, credential separation, and CloudTrail are the enforceable controls.
Codex must not receive mutation-capable credentials. Safe future mutation
support requires a separate plan → human approval → one-shot broker architecture;
`PreToolUse ask`, user rules, or a local token are not sufficient.

The Codex hook supervisor fails closed if Python/classification crashes or emits
malformed output. The current Codex shell integration targets macOS/Linux with
Python 3.8 or newer.
