#!/usr/bin/env bash
# Offline tests for aws-shim.sh. Never touches real AWS, the network, or your
# real home. A fake `aws` on PATH stands in for the real binary and prints a
# marker when it runs; the REAL frozen gate classifies commands via a
# throwaway policy in a temp HOME. Exit 0 when every case passes.
#
# Cases asserted:
#   1. an allowed read runs the fake aws
#   2. a denied unstamped mutation does NOT run it and returns nonzero
#   3. an ask path answered "no" does NOT run it and returns nonzero
#   4. (bonus) an ask path answered "yes" DOES run it
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SHIM="$HERE/aws-shim.sh"
GATE="$HERE/classify-aws-command.py"

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# --- Fake real aws binary: first `aws` on PATH, prints a marker and exits 0 ---
MARKER="REAL-AWS-RAN"
BIN="$SANDBOX/bin"
mkdir -p "$BIN"
cat > "$BIN/aws" <<EOF
#!/usr/bin/env bash
echo "$MARKER \$*"
exit 0
EOF
chmod +x "$BIN/aws"

# --- Throwaway policy so the gate classifies without any real account -------
POLICY="$SANDBOX/policy.json"
cat > "$POLICY" <<'EOF'
{
  "operator": { "name": "test-operator", "stamp_prefix": "xx" },
  "profiles": { "acct-read": "readonly", "acct-admin": "admin" },
  "required_tags": { "team": "example-team" },
  "ledger": false
}
EOF

# --- Sandbox every path that could touch a real home or config -------------
export HOME="$SANDBOX/home"
mkdir -p "$HOME/.claude"
export AWS_OPS_POLICY_FILE="$POLICY"
export AWS_OPS_LEDGER_FILE="$SANDBOX/ledger.jsonl"
export AWS_OPS_GATE="$GATE"
export PATH="$BIN:$PATH"          # fake aws wins for `command aws`
unset AWS_OPS_SHIM_CONFIRM 2>/dev/null || true

# Source the shim; this defines the `aws` function in THIS shell.
# shellcheck disable=SC1090
. "$SHIM"

pass=0; fail=0
report() { # name ok-bool detail
  if [ "$2" -eq 1 ]; then pass=$((pass+1)); echo "PASS  $1";
  else fail=$((fail+1)); echo "FAIL  $1  ($3)"; fi
}

# 1. Allowed read -> fake aws runs.
out="$(aws sts get-caller-identity --profile acct-read 2>&1)"; rc=$?
ok=1
printf '%s' "$out" | grep -q "$MARKER" || ok=0
[ "$rc" -eq 0 ] || ok=0
report "allowed read runs the real (fake) aws" "$ok" "rc=$rc out=$out"

# 2. Denied unstamped mutation -> does NOT run, nonzero.
out="$(aws ec2 create-tags --resources vol-0abc --tags Key=env,Value=prod --profile acct-admin 2>&1)"; rc=$?
ok=1
printf '%s' "$out" | grep -q "$MARKER" && ok=0        # must NOT have run
[ "$rc" -ne 0 ] || ok=0                                # must be nonzero
printf '%s' "$out" | grep -qi "deny" || ok=0
report "denied unstamped mutation does not run, returns nonzero" "$ok" "rc=$rc out=$out"

# 3. Ask path answered "no" -> does NOT run, nonzero.
out="$(AWS_OPS_SHIM_CONFIRM=no aws secretsmanager get-secret-value --secret-id app/db --profile acct-admin 2>&1)"; rc=$?
ok=1
printf '%s' "$out" | grep -q "$MARKER" && ok=0        # must NOT have run
[ "$rc" -ne 0 ] || ok=0
printf '%s' "$out" | grep -qi "ask" || ok=0
report "ask path answered no does not run, returns nonzero" "$ok" "rc=$rc out=$out"

# 4. Bonus: ask path answered "yes" -> DOES run.
out="$(AWS_OPS_SHIM_CONFIRM=yes aws secretsmanager get-secret-value --secret-id app/db --profile acct-admin 2>&1)"; rc=$?
ok=1
printf '%s' "$out" | grep -q "$MARKER" || ok=0        # must have run
[ "$rc" -eq 0 ] || ok=0
report "ask path answered yes runs the real (fake) aws" "$ok" "rc=$rc out=$out"

# 5. Bonus: fail-closed when the gate is missing.
out="$(AWS_OPS_GATE="$SANDBOX/nope.py" aws sts get-caller-identity --profile acct-read 2>&1)"; rc=$?
ok=1
printf '%s' "$out" | grep -q "$MARKER" && ok=0        # must NOT have run
[ "$rc" -ne 0 ] || ok=0
report "missing gate fails closed (refuses, nonzero)" "$ok" "rc=$rc out=$out"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
