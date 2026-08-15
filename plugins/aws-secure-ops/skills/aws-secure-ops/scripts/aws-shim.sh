# aws-shim.sh — opt-in terminal seatbelt for the aws CLI (bash + zsh).
#
# Source this from your ~/.zshrc or ~/.bashrc:
#
#     source /path/to/aws-shim.sh
#
# It defines a shell function named `aws` that classifies each invocation
# through the local aws-secure-ops gate (classify-aws-command.py) BEFORE the
# real aws binary runs:
#
#     allow  -> runs the real aws with your original arguments
#     deny   -> prints the reason, runs nothing, returns nonzero
#     ask    -> prints the reason and asks you to confirm; runs only on "yes"
#
# ---------------------------------------------------------------------------
# THIS IS BEST-EFFORT AND TRIVIALLY BYPASSABLE. IT IS A NET AGAINST
# CARELESSNESS, NOT A SECURITY CONTROL.
#
#   - `command aws ...`, `/usr/bin/aws ...` (any path-qualified binary), or
#     any other tool that talks to AWS all skip this function entirely.
#   - `unset -f aws` removes it for the current shell.
#
# The REAL controls are IAM and SCPs on the AWS side. This shim only helps a
# careful operator avoid an obvious slip; it stops nothing that is trying to
# get around it. Fail-closed by design: if it cannot classify a command
# (missing python, missing gate, gate error, no terminal to confirm) it
# REFUSES to run aws rather than letting it through silently.
# ---------------------------------------------------------------------------

# Resolve the directory holding this script at source time, portably across
# bash and zsh. The zsh-only expansion is hidden inside `eval` so bash never
# has to parse it. AWS_OPS_GATE (evaluated per-call) overrides the gate path.
if [ -n "${ZSH_VERSION:-}" ]; then
  eval '_AWS_SHIM_SRC="${(%):-%x}"'
else
  _AWS_SHIM_SRC="${BASH_SOURCE[0]:-$0}"
fi
_AWS_SHIM_DIR="$(cd "$(dirname "$_AWS_SHIM_SRC")" 2>/dev/null && pwd)"
unset _AWS_SHIM_SRC

# A pre-existing `aws` alias would make the `aws()` definition below a parse
# error in both bash and zsh -- silently leaving the alias in place and every
# aws command ungated, the exact opposite of this shim's fail-closed promise.
# Remove it before defining the function. Aliases are expanded as a line is
# read, so this must be its own line, read and run before `aws() {` is parsed;
# quoting the name also defuses zsh global-alias expansion of the word here.
unalias "aws" 2>/dev/null || true

aws() {
  # All state is local so nothing leaks into the interactive shell.
  local _py _gate _event _out _rc _parsed _decision _reason _ans _c

  # 1a. Find a python interpreter (do not hardcode a path). Fail closed.
  _py=""
  for _c in python3 python; do
    if command -v "$_c" >/dev/null 2>&1; then _py="$_c"; break; fi
  done
  if [ -z "$_py" ]; then
    printf '%s\n' "aws-shim: no python3 found; refusing to run aws unclassified (fail closed)." >&2
    printf '%s\n' "aws-shim: use 'command aws ...' to bypass, or 'unset -f aws' to disable." >&2
    return 1
  fi

  # 1b. Resolve the gate. It sits next to this script; AWS_OPS_GATE overrides.
  _gate="${AWS_OPS_GATE:-$_AWS_SHIM_DIR/classify-aws-command.py}"
  if [ ! -f "$_gate" ]; then
    printf '%s\n' "aws-shim: gate not found at '$_gate'; refusing (fail closed)." >&2
    printf '%s\n' "aws-shim: set AWS_OPS_GATE, or 'unset -f aws' to disable." >&2
    return 1
  fi

  # 2. Build the PreToolUse hook event JSON. Python does the shell-quoting of
  #    every argument and the JSON escaping, so arbitrary argv round-trips
  #    safely — no eval, no hand-rolled quoting. The program is fed on stdin
  #    (python's `-`), the aws arguments arrive as sys.argv.
  _event="$("$_py" - "$@" <<'PYEOF'
import json, shlex, sys
args = sys.argv[1:]
cmd = "aws " + " ".join(shlex.quote(a) for a in args) if args else "aws"
sys.stdout.write(json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}))
PYEOF
)"
  if [ $? -ne 0 ] || [ -z "$_event" ]; then
    printf '%s\n' "aws-shim: could not encode the command for the gate; refusing (fail closed)." >&2
    return 1
  fi

  # 3. Pipe the event to the gate. The gate prints a decision JSON, or exits 0
  #    with NO output to mean allow. A nonzero gate exit is an unexpected
  #    crash: treat it conservatively and refuse.
  _out="$(printf '%s' "$_event" | "$_py" "$_gate" 2>/dev/null)"
  _rc=$?
  if [ "$_rc" -ne 0 ]; then
    printf '%s\n' "aws-shim: gate error (exit $_rc); refusing (fail closed)." >&2
    printf '%s\n' "aws-shim: use 'command aws ...' to bypass, or 'unset -f aws' to disable." >&2
    return 1
  fi

  # Empty output is the gate's silent-allow contract.
  if [ -z "$_out" ]; then
    command aws "$@"
    return $?
  fi

  # Parse decision + reason. Any parse failure falls to a conservative ask.
  _parsed="$(printf '%s' "$_out" | "$_py" -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("allow"); print(""); sys.exit(0)
try:
    h = json.loads(raw)["hookSpecificOutput"]
    print(h.get("permissionDecision") or "ask")
    print((h.get("permissionDecisionReason") or "").replace("\n", " ").replace("\r", " "))
except Exception:
    print("ask")
    print("aws-shim could not parse the gate response; confirm manually.")
')"
  _decision="${_parsed%%$'\n'*}"
  _reason="${_parsed#*$'\n'}"
  [ "$_reason" = "$_decision" ] && _reason=""

  case "$_decision" in
    allow)
      command aws "$@"
      return $?
      ;;
    deny)
      printf '%s\n' "aws-shim DENY: ${_reason:-blocked by the aws-secure-ops gate}" >&2
      return 1
      ;;
    ask)
      printf '%s\n' "aws-shim ASK: ${_reason:-this command needs confirmation}" >&2
      # Non-interactive answer override (documented, opt-in, e.g. for tests
      # or automation). Any value that is not an explicit yes counts as no.
      if [ -n "${AWS_OPS_SHIM_CONFIRM:-}" ]; then
        _ans="$AWS_OPS_SHIM_CONFIRM"
      elif [ -r /dev/tty ]; then
        printf 'Run this aws command anyway? [y/N] ' >&2
        IFS= read -r _ans < /dev/tty || _ans=""
      else
        printf '%s\n' "aws-shim: no terminal to confirm; refusing (fail closed)." >&2
        return 1
      fi
      case "$_ans" in
        y|Y|yes|Yes|YES)
          command aws "$@"
          return $?
          ;;
        *)
          printf '%s\n' "aws-shim: not confirmed; command not run." >&2
          return 1
          ;;
      esac
      ;;
    *)
      printf '%s\n' "aws-shim: unrecognized gate decision '${_decision}'; refusing (fail closed)." >&2
      return 1
      ;;
  esac
}

# Fail loud, not open: if the function did not install (an exotic shell, a
# parse error, a stubborn alias), say so rather than let aws run ungated.
if ! typeset -f aws >/dev/null 2>&1; then
  printf '%s\n' "aws-shim: FAILED to install the aws gate function; aws is UNGATED in this shell." >&2
fi
