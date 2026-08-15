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
