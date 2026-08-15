#!/usr/bin/env bash
# Tests for run-gate.sh, the interpreter-resolving hook launcher. Offline: no AWS
# calls. Verifies (1) the happy path execs the real gate with a byte-identical
# decision, and (2) the no-interpreter path fails CLOSED for aws-shaped commands
# while staying silent for everything else.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
WRAP="$DIR/run-gate.sh"
GATE="$DIR/classify-aws-command.py"
POLICY="$(mktemp)"
LEDGER="$(mktemp)"
BIN="$(mktemp -d)"
trap 'rm -f "$POLICY" "$LEDGER" "$BIN"/cat "$BIN"/grep; rmdir "$BIN" 2>/dev/null || true' EXIT
printf '{}' >"$POLICY"
export AWS_OPS_POLICY_FILE="$POLICY" AWS_OPS_LEDGER_FILE="$LEDGER"

pass=0
fail=0
check() { # label got want
  if [ "$2" = "$3" ]; then
    pass=$((pass + 1))
    echo "PASS  $1"
  else
    fail=$((fail + 1))
    echo "FAIL  $1  (got '$2' want '$3')"
  fi
}

MUT='{"tool_name":"Bash","tool_input":{"command":"aws ec2 delete-volume --volume-id v --profile x"}}'
NONAWS='{"tool_name":"Bash","tool_input":{"command":"ls -la /tmp"}}'

# 1. Happy path: the wrapper's decision equals invoking the gate directly.
w=$(printf '%s' "$MUT" | sh "$WRAP" "$GATE" | tr -d '[:space:]')
d=$(printf '%s' "$MUT" | python3 "$GATE" | tr -d '[:space:]')
check "happy path: wrapper decision == direct gate" "$w" "$d"

# 2. No-interpreter fallback: build a PATH with cat/grep but no python*.
for t in cat grep; do
  rp=$(command -v "$t" 2>/dev/null || true)
  [ -x "$rp" ] && ln -s "$rp" "$BIN/$t"
done
if PATH="$BIN" /bin/sh -c 'command -v python3 python py' >/dev/null 2>&1; then
  echo "SKIP  no-interpreter tests (a python* is reachable under the restricted PATH)"
else
  m=$(printf '%s' "$MUT" | PATH="$BIN" /bin/sh "$WRAP" "$GATE" | grep -o '"permissionDecision":"deny"' || true)
  check "no interpreter: aws-shaped command is denied (fail closed)" "$m" '"permissionDecision":"deny"'
  n=$(printf '%s' "$NONAWS" | PATH="$BIN" /bin/sh "$WRAP" "$GATE" | wc -c | tr -d ' ')
  check "no interpreter: non-aws command stays silent" "$n" "0"
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
