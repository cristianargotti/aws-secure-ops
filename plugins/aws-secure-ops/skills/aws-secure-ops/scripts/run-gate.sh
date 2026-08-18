#!/bin/sh
# Interpreter-resolving launcher for the aws-secure-ops PreToolUse gate and the
# SessionStart watchdog. hooks.json routes both hooks through this so the plugin
# does not depend on a bare `python3` being first on PATH (Windows ships `python`
# or the `py` launcher; some minimal images ship neither).
#
# Normal case: resolve python3 / python / py and exec it with the gate script and
# args, passing the hook event through on stdin unchanged -- the decision is then
# byte-identical to invoking the gate directly.
#
# Degraded case (NO interpreter at all): fail CLOSED, not open. For the gate, a
# Bash command that looks like an aws invocation is denied (via the same JSON the
# gate emits) rather than left to run unclassified; anything else, and the
# watchdog, stay silent so ordinary work is never blocked.

_codex_deny() {
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"aws-secure-ops failed closed: the Codex classifier did not complete with a valid blocking decision. AWS-capable shell execution is blocked until the hook is healthy."}}'
}

_codex_warn() {
  printf '%s\n' '{"systemMessage":"aws-secure-ops watchdog: the Codex hook launcher or doctor failed; treat the AWS seatbelt as unhealthy until the offline doctor passes."}'
}

_codex_sanitize_launcher() {
  _unsafe=""
  for _name in \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP PYTHONWARNINGS \
    PYTHONBREAKPOINT PYTHONUSERBASE LD_PRELOAD LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH SSLKEYLOGFILE; do
    eval '_value=${'"$_name"':-}'
    if [ -n "$_value" ]; then
      _unsafe="${_unsafe}${_unsafe:+,}${_name}"
    fi
  done
  AWS_OPS_UNSAFE_LAUNCH_ENV="$_unsafe"
  export AWS_OPS_UNSAFE_LAUNCH_ENV
  unset PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP PYTHONWARNINGS
  unset PYTHONBREAKPOINT PYTHONUSERBASE LD_PRELOAD LD_LIBRARY_PATH
  unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
  unset SSLKEYLOGFILE
}

_codex_python() {
  for _candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$_candidate" ] &&
      "$_candidate" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$_candidate"
      return 0
    fi
  done
  return 1
}

_codex_lock_runtime_paths() {
  _home="$($1 -I -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)' 2>/dev/null)"
  case "$_home" in
    /*) ;;
    *) return 1 ;;
  esac
  if [ -n "${PLUGIN_ROOT:-}" ]; then
    if [ "${HOME:-}" != "$_home" ]; then
      AWS_OPS_UNSAFE_LAUNCH_ENV="${AWS_OPS_UNSAFE_LAUNCH_ENV}${AWS_OPS_UNSAFE_LAUNCH_ENV:+,}HOME"
      export AWS_OPS_UNSAFE_LAUNCH_ENV
    fi
    HOME="$_home"
    AWS_OPS_POLICY_FILE="$_home/.claude/aws-ops.policy.json"
    AWS_OPS_LEDGER_FILE="$_home/.codex/aws-secure-ops-ledger.jsonl"
    export HOME AWS_OPS_POLICY_FILE AWS_OPS_LEDGER_FILE
  fi
  return 0
}

# Codex does not block a tool call merely because a hook process crashes or
# emits malformed JSON. Its lane therefore uses this supervising launcher:
# classifier failures become a syntactically valid deny, while watchdog
# failures become a visible SessionStart warning. Use only known absolute
# interpreter paths so a command-local PATH override cannot select another
# binary.
case "${1:-}" in
  --codex-pretool)
    shift
    _codex_sanitize_launcher
    _event="$(/bin/cat)"
    # Never let the parent task redefine the executable trust anchor. Python
    # isolated mode also ignores PYTHON* injection and user sitecustomize.
    unset AWS_OPS_TRUSTED_AWS_CLI
    _py="$(_codex_python)"
    if [ -z "$_py" ]; then
      _codex_deny
      exit 0
    fi
    if ! _codex_lock_runtime_paths "$_py"; then
      _codex_deny
      exit 0
    fi
    _out="$(printf '%s' "$_event" | "$_py" -I "$@" 2>/dev/null)"
    _status=$?
    if [ "$_status" -ne 0 ]; then
      _codex_deny
      exit 0
    fi
    if [ -z "$_out" ]; then
      exit 0
    fi
    if printf '%s' "$_out" | "$_py" -I -c 'import json,sys; p=json.load(sys.stdin); h=p.get("hookSpecificOutput", {}) if isinstance(p, dict) else {}; ok=h.get("hookEventName") == "PreToolUse" and h.get("permissionDecision") == "deny" and isinstance(h.get("permissionDecisionReason"), str); raise SystemExit(0 if ok else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$_out"
    else
      _codex_deny
    fi
    exit 0
    ;;
  --codex-session)
    shift
    _codex_sanitize_launcher
    _event="$(/bin/cat)"
    unset AWS_OPS_TRUSTED_AWS_CLI
    _py="$(_codex_python)"
    if [ -z "$_py" ]; then
      _codex_warn
      exit 0
    fi
    if ! _codex_lock_runtime_paths "$_py"; then
      _codex_warn
      exit 0
    fi
    _out="$(printf '%s' "$_event" | "$_py" -I "$@" 2>/dev/null)"
    _status=$?
    if [ "$_status" -ne 0 ]; then
      _codex_warn
      exit 0
    fi
    if [ -z "$_out" ]; then
      exit 0
    fi
    if printf '%s' "$_out" | "$_py" -I -c 'import json,sys; p=json.load(sys.stdin); ok=isinstance(p, dict) and isinstance(p.get("systemMessage"), str); raise SystemExit(0 if ok else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$_out"
    else
      _codex_warn
    fi
    exit 0
    ;;
esac

for _c in python3 python py; do
  # Verify the candidate is actually Python 3 before trusting it: a legacy
  # `python` (Python 2) or a stub would run the gate into a crash and fail open.
  if command -v "$_c" >/dev/null 2>&1 &&
    "$_c" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
    exec "$_c" "$@"
  fi
done

# No interpreter found. Read the hook event so stdin is consumed either way.
_event="$(cat)"

case "$*" in
  *classify-aws-command.py*)
    # PreToolUse gate: deny only when the event's command looks like an aws
    # invocation (erring strict is safe here -- this path is reached only on a
    # host with no Python, which the operator needs to fix regardless).
    if printf '%s' "$_event" | grep -Eq 'aws([[:space:]]|\\[tn])'; then
      printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"aws-secure-ops: no Python interpreter found on PATH; aws commands are blocked until python3 (or python) is installed. Fail-closed by design."}}'
    fi
    exit 0
    ;;
  *)
    # SessionStart watchdog (or anything else): never block the session.
    exit 0
    ;;
esac
