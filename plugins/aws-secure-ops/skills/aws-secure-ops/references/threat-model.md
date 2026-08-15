# Threat model: what the gate is, catches, and cannot catch

A security control that overstates its coverage is worse than no control,
because people lean on the coverage it does not have. This document is the
candid account of the enforcement gate (`scripts/classify-aws-command.py`):
its trust model, the exact list of what it intercepts, the blind spots it
cannot close, the layers that compensate for each blind spot, and how the
gate itself behaves when it breaks.

Read this before trusting the gate with anything, and re-read it before
arguing that the gate makes some other control unnecessary. It never does.

## Trust model

**Valid instructions come from the operator.** The gate is not an
authentication or authorization system; it assumes the human driving the
session is the accountable operator and exists to keep that operator's
hands honest, not to stop an adversary who controls the session.

**Everything the gate inspects is a command string.** It parses the text of
a shell command before execution. Text is not behavior: the gate knows what
the command _says_, never what the process will _do_, what a referenced
file _contains_, or what credentials the environment will _actually_
resolve. Every guarantee below is a guarantee about strings.

**The gate is an advisory seatbelt layered on top of IAM.** Least privilege
in the role is the real control: privilege the role does not carry cannot
be misused no matter what reaches the API. Service control policies and
permission boundaries enforce organizational limits server-side, where no
client-side tool can un-enforce them. The gate sits in front of all of
that and lowers the probability that a careless keystroke ever becomes an
API call. It replaces nothing. A session in which the gate is the only
thing standing between a keystroke and a disaster is misconfigured at the
IAM layer, and fixing that is the priority.

**Deny and ask are the gate's only powers; allow is silence.** The gate
emits a deny or a request for human confirmation through the harness's
permission protocol, or it exits silently and the normal permission system
proceeds as if the gate did not exist. It never auto-approves anything.

## What the gate catches

The following is enumerated from the code, not from intent. Classification
comes from the full inventory of the installed CLI
(`references/inventory/inventory.csv`: class, sensitivity, per-operation
rules), with a verb taxonomy as fallback; an operation whose _verb_ the
taxonomy does not know is treated as a sensitive guarded mutation. (An
unknown-_service_ operation whose name starts with a read verb still classifies
as a read — see the residual noted below.)

### Denied outright

| Pattern                              | Mechanics                                                                                                                                                                                                                                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| TLS verification disabled            | `--no-verify-ssl` anywhere in the command, checked before anything else.                                                                                                                                                                                                                         |
| Frozen-profile mutation              | Any non-read operation whose resolved profile (from `--profile`, an inline `AWS_PROFILE=`, or an `AWS_PROFILE` exported earlier in the command) is classified `frozen` by the local policy.                                                                                                      |
| Mass mutation via loop or dispatcher | A mutating operation reached through a `for`/`while`/`until` loop head (at a segment start or inside command substitution), an `xargs ... aws` pipeline, a `find ... -exec ... aws` action, or a GNU `parallel ... aws` dispatch. One target per mutating command is the rule the deny enforces. |
| Unstamped mutation                   | Any non-read invocation without an inline `AWS_SDK_UA_APP_ID=` assignment in its own shell segment (personal-class profiles exempt).                                                                                                                                                             |
| Malformed purpose stamp              | Stamp longer than 50 characters; stamp containing a tool/automation marker; stamp missing the operator prefix when the local policy defines one.                                                                                                                                                 |
| Automation markers in tags           | Tool/automation markers inside `--tags`, `--tag-specifications`, or `--tagging` values. Audit-visible values name the accountable human, never the tooling.                                                                                                                                      |

### Escalated to human confirmation

| Pattern                | Mechanics                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Destructive operations | Worst class across the command is `destroy`; the prompt restates look-before-delete.                                                                                                                                                                                                                                                                                                      |
| Sensitive operations   | Inventory-flagged trust/exposure/spend/disruption operations, plus flag escalations: `s3 sync --delete` reclassified as destructive, `--force` on a mutation, public ACL grants (`--acl public-read` and friends), `--with-decryption`. Policy-writing operations (`iam put-role-policy`, `s3api put-bucket-policy`, and peers) land here regardless of where the policy body comes from. |
| Secret-material reads  | Inventory-flagged credential reads (`secretsmanager get-secret-value`, `kms decrypt`, `ssm get-parameter`, `sts assume-role`, `configure export-credentials`, ...) prompt with the pipe-to-consumer rule so the value never lands in a transcript.                                                                                                                                        |
| Non-AWS endpoint       | `--endpoint-url` whose host is not under `amazonaws.com`/`amazonaws.com.cn` and is not localhost. Redirecting signed requests to a foreign host is a credential-exfiltration pattern; the gate demands intent be stated.                                                                                                                                                                  |
| Untagged creates       | A `create`-class operation with no tagging flag while the local policy declares required tags.                                                                                                                                                                                                                                                                                            |

### Parsing behavior that resists casual evasion

- The gate detects `aws` invocations nested inside command substitution and
  backticks, and path-prefixed binaries (`/usr/local/bin/aws`), not just a
  leading `aws` token.
- Judgment is per shell segment. A purpose stamp never carries across
  segments: a mutation relying on a stamp set earlier in the chain
  (`AWS_SDK_UA_APP_ID=y ... && aws ...`) still arrives unstamped and is
  denied. A persisted `AWS_PROFILE` is the one value tracked forward -- an
  `export AWS_PROFILE=<frozen>` (or a bare assignment segment) reaches the
  frozen-profile check for later invocations, so `export`-then-mutate
  cannot dodge a freeze. That carry only ever adds strictness; it never
  grants the personal-profile exemption, which still needs an explicit
  profile on the invocation itself. Where the splitter over-splits, the
  error is always toward the stricter judgment.
- Unknown **verbs** classify as guarded mutations (modify, sensitive), so a
  newly-named mutating operation gets a strict lane until the inventory is
  regenerated. But classification falls back to the verb alone regardless of
  service: an operation of a service _newer than the inventory_ whose name
  begins with a read verb (get/list/describe/...) classifies as an ordinary
  read and passes unstamped. That is a residual worth naming — a brand-new
  service could name a credential-emitting operation `get-*` — and the fix is
  to regenerate the inventory after a CLI upgrade so the celebrated exceptions
  are re-encoded.

## What the gate does not and cannot catch

Bluntly, string inspection has a floor, and these sit below it. Each item
names the residual risk and the control that actually covers it.

**Ambient credentials and pre-exported profiles.** The gate sees the
command string of the current invocation. An `AWS_PROFILE` exported before
this session started, credentials in `~/.aws/credentials` default
sections, instance metadata, or an `AWS_ACCESS_KEY_ID` sitting in the
environment are all invisible: a mutation under an ambient frozen or admin
profile passes the gate's profile checks because no profile appears in the
string. _Residual:_ the gate can misjudge which principal a command will
run as. _Compensating controls:_ the protocol's rule to name `--profile`
explicitly on every command; the identity gate (`sts get-caller-identity`
before the first call of a task); and, for anything that must truly never
mutate, enforcement where it belongs, in the credential lifecycle (expire
or detach the keys) and in a deny SCP that no client-side state can
override.

**Contents of `file://` inputs and policy bodies.** The gate sees that a
policy-writing operation is happening and escalates it to confirmation,
but it never opens the file. A trust policy with a wildcard principal, a
bucket policy open to the world, or a template that replaces a stateful
resource all pass through the gate looking identical to their safe
counterparts. _Residual:_ the most dangerous byte of a mutation is often
in a file the gate never reads. _Compensating controls:_ the mutation
ladder (read the document, simulate the policy, review the change set
before executing); the human confirmation the gate forces on these
operations, which exists precisely so a person looks at the body; and
server-side analyzers and organizational guardrails that evaluate the
resulting state rather than the request text.

**Genuinely novel obfuscation.** Anyone determined can beat a string
matcher: write the command into a script and execute the script, build it
with `eval` or base64, alias the binary, or drive mass mutation through a
wrapper the loop detector does not model (a Makefile target, a bespoke
runner). The common dispatchers are covered -- shell loops, `xargs`,
`find -exec`, and `parallel` all trip the mass-mutation deny -- but the
set is finite and never exhaustive. Each spawned invocation still visible
in the string is classified and still needs its stamp. _Residual:_ the
gate is a control against carelessness, not against intent; a session
actively working to evade it will succeed. _Compensating controls:_ least
privilege caps what an evaded gate can reach; CloudTrail records the real
API calls regardless of how they were dressed locally; and evasion itself
is the signal, since a transcript that obfuscates its own commands reads
as exactly what it is.

**Anything outside the aws CLI in this harness.** The gate is a pre-tool
hook on this harness's shell tool. SDK scripts (boto3, the JS SDK), the
web console, Terraform or CDK applies, raw signed HTTP, and aws commands
typed into any other terminal never pass through it. _Residual:_ an entire
parallel path to the same APIs with zero gate coverage. _Compensating
controls:_ IAM, SCPs, and permission boundaries are tool-agnostic and bind
every path equally; the operating protocol (stamping via the SDK's
user-agent app id, one target per mutation, read-back verification) is a
discipline that travels with the operator, not with the tool; and the
audit trail records every path identically. The opt-in terminal shim
(`scripts/aws-shim.sh`) reclaims one slice of this surface -- interactive
`aws` in an ordinary shell -- by routing it through the same classifier,
but it is best-effort by construction: it hooks a shell function, so a
path-qualified binary (`/usr/bin/aws`), a different shell, or any of the
non-CLI paths above walks straight past it. It narrows the blind spot; it
does not close it, and it earns exactly the same honesty as the console and
SDK gaps -- the server-side controls remain the real coverage.

**Frozen-by-name enforcement without a loaded policy file.** Profile
classes live in the local policy file. Without it, the gate has no notion
of which profile is frozen, personal, or admin: the frozen deny cannot
fire, the required-tags prompt is inert, and the stamp-prefix check is
skipped. The baseline rules (stamps on mutations, loop denial, sensitive
and destructive confirmation, endpoint and TLS checks) still apply in
full. _Residual:_ on a machine without the policy file, "frozen" is a
convention, not a control. _Compensating controls:_ a freeze that matters
is implemented as detached credentials and a deny SCP, so the account
refuses the mutation no matter which client asks; the policy file is the
local convenience mirror of that decision, not its substance.

## Defense in depth: why no single failure is catastrophic

The layers stack so that each one's failure is caught by a neighbor:

1. **SCPs and permission boundaries** (server-side, organizational). Bind
   every tool and every session; cannot be bypassed by anything a client
   does. Catch: gate evasion, SDK paths, console actions, stolen sessions.
2. **Least-privilege profiles** (server-side, per-session). The role is
   the hard cap on blast radius; a read-only session cannot mutate even if
   every local control fails simultaneously. Catch: careless commands the
   gate misparsed, ambient-credential surprises.
3. **The gate** (client-side, pre-execution). Catches the careless
   keystroke before it becomes an API call, at the moment it is cheapest
   to catch. Catch: unstamped, looped, frozen, unconfirmed-destructive
   mistakes that IAM would have permitted.
4. **The local decision ledger** (client-side, post-decision). One
   metadata line per inspected invocation, by contract never command text
   or secret material: timestamp, service, operation, class, sensitivity,
   decision, stamp, profile. Gives the operator an honest local answer to
   "what did I actually run", and `scripts/aws-ops-ledger.py` turns it
   into stamp-by-stamp reconciliation against the audit trail.
5. **Purpose stamps in CloudTrail** (server-side, per-event). Intent
   travels inside the authoritative record itself (`app/<stamp>` in the
   userAgent), so a reviewer reconstructs the why without the operator in
   the room, even if every local artifact is lost.
6. **Read-back verification** (protocol). A mutation is not done when the
   command exits zero; it is done when a read proves the intended state.
   Catch: partial failures, eventual-consistency surprises, and the gap
   between what a command said and what the service did, which is exactly
   the gap the gate cannot see.

Trace any single failure through the stack: a gate bug is bounded by the
role; an over-privileged role is bounded by the SCP; a lost ledger is
recoverable from CloudTrail; a missing stamp is denied by the gate before
it happens; a lying exit code is caught by the read-back. The design
assumption is that each layer will fail eventually, alone.

## Failure modes of the gate itself

- **Unparseable hook input, or a non-shell tool.** The gate exits silently
  with no opinion, and the harness's normal permission system proceeds
  exactly as if the gate were absent. This is deliberate: a broken gate
  must degrade to the pre-gate baseline, not become a wall in front of all
  work, and it can degrade safely only because it was never the sole
  authorization layer.
- **Unparseable shell segment.** Tokenization falls back from proper shell
  lexing to whitespace splitting, and segment over-splitting errs toward
  the stricter judgment, so a command the gate half-understands is judged
  more harshly, not waved through.
- **Missing or corrupt inventory.** Classification falls back to the verb
  taxonomy, and any verb the taxonomy does not know classifies as a
  sensitive guarded mutation. A gate that has lost its data becomes more
  suspicious, not less.
- **Missing or invalid policy file.** The gate falls back to conservative
  defaults, with the honest caveat documented above: the baseline rules
  hold, but policy-specific rules (frozen profiles, required tags, stamp
  prefix) silently do not. This is the one degradation that loosens rather
  than tightens, which is exactly why a real freeze is implemented in the
  credential lifecycle and SCPs, never only in the policy file.
- **Unwritable or corrupted ledger.** The ledger is evidence, not
  authorization: a failed write costs a line of local history, never a
  blocked or silently permitted operation. The authoritative record is
  server-side in CloudTrail and does not depend on any local file; the
  ledger CLI reads defensively, skips malformed lines with a warning, and
  errors loudly on an unreadable file rather than pretending the history
  is complete.

The through-line: when the gate degrades, it degrades toward either
stricter judgment or the pre-existing permission baseline, and the layers
above and below it are sized on the assumption that some days it
contributes nothing. That assumption, stated plainly, is what makes it
safe to rely on the gate on all the other days.

## Packaging layers: the watchdog and the plugin toggle

Two packaging-level layers sit above the runtime stack. The **watchdog**
closes the one gap the silent-degradation design leaves open: because a
broken gate falls back to the permission baseline without a word, a session
could otherwise run for hours believing it was protected when it was not. A
`SessionStart` health check (`scripts/aws-ops-doctor.py --quick`) runs at the
start of every session, stays quiet when the seatbelt is sound, and speaks
only to warn that it has come loose -- gate unregistered, policy invalid,
inventory inconsistent with its own summary. (It does not auto-detect drift
against the _installed_ CLI; that check is `scripts/build-inventory.py` +
`scripts/verify-inventory.py`, re-run after a CLI upgrade.) A silently broken
seatbelt now announces itself. It is a warning, not a wall: it never blocks
work, only
tells you the odds changed.

And because the whole thing ships as one plugin, **"off" is explicit and
total**: the gate, the skill, and the watchdog toggle as a single unit, so
there is no half-disabled state to reason about. The control is either
present and self-checking, or deliberately and visibly gone -- and when it is
gone, the server-side controls (IAM, SCPs, permission boundaries, read-only
roles) carry the load exactly as they did before, which is the whole reason
it is safe to make the toggle a real one.
