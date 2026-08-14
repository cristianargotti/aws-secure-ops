#!/usr/bin/env bash
# =============================================================================
# Living security regression corpus for classify-aws-command.py
# =============================================================================
# This is the growing evasion-only catalogue for the aws command gate. Unlike
# the broad functional suite (test-gate-hardening.sh), every case here is an
# EVASION VECTOR: a way an operator (human or automated) might try to smuggle a
# mutation, exposure, or misattribution past the gate. Each case asserts the
# SAFE decision — the dangerous vectors must be caught (deny/ask), and the
# benign lookalikes must stay allowed so the gate never blocks honest work.
#
# The contract of this file: when a new bypass is discovered and closed in the
# gate, a case is added here that reproduces the vector and pins the safe
# decision, so the same hole can never silently reopen. The corpus only grows.
#
# Fully offline: no real aws, no network, no AWS account, no credentials. The
# gate is exercised ONLY by piping a hook-event JSON to it, exactly the way the
# PreToolUse hook does at runtime — never by typing a raw aws command into this
# shell. The gate itself is frozen and is never modified by this suite.
#
# Portable across macOS and Linux, bash and zsh: the interpreter is discovered,
# not hardcoded; no BSD-only flags are used. Fails closed — any case that does
# not produce its expected safe decision counts as a failure and the suite
# exits nonzero.
# =============================================================================
set -u

# --- Discover a Python 3 interpreter (do not hardcode a path) ----------------
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
      PY="$cand"
      break
    fi
  fi
done
if [ -z "$PY" ]; then
  echo "FATAL: no python3 interpreter found on PATH" >&2
  exit 2
fi

GATE="$(cd "$(dirname "$0")" && pwd)/classify-aws-command.py"
if [ ! -f "$GATE" ]; then
  echo "FATAL: gate not found at $GATE" >&2
  exit 2
fi

# --- Throwaway policy + ledger, sandboxed HOME (never touch the real one) ----
POLICY="$(mktemp)"
LEDGER="$(mktemp)"
SANDBOX_HOME="$(mktemp -d)"
trap 'rm -rf "$POLICY" "$LEDGER" "$SANDBOX_HOME"' EXIT

cat > "$POLICY" <<'EOF'
{
  "operator": { "name": "test-operator", "stamp_prefix": "xx" },
  "profiles": {
    "acct-read": "readonly",
    "acct-admin": "admin",
    "legacy-frozen": "frozen",
    "hobby": "personal"
  },
  "required_tags": { "environment": "production", "team": "example-team" }
}
EOF

export HOME="$SANDBOX_HOME"
export AWS_OPS_POLICY_FILE="$POLICY"
export AWS_OPS_LEDGER_FILE="$LEDGER"
export PYTHONUTF8=1  # so invisible-character stamp cases round-trip through argv

pass=0; fail=0

run_case() { # name command expected(allow|deny|ask) [reason-substring]
  local name="$1" cmd="$2" want="$3" substr="${4:-}"
  local out decisionv
  out=$(printf '%s' "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$("$PY" -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")}}" | "$PY" "$GATE" 2>&1)
  if [ -z "$out" ]; then decisionv="allow"; else
    decisionv=$(printf '%s' "$out" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])' 2>/dev/null || echo "parse-error")
  fi
  local ok=1
  [ "$decisionv" = "$want" ] || ok=0
  if [ -n "$substr" ] && ! printf '%s' "$out" | grep -qi "$substr"; then ok=0; fi
  if [ $ok -eq 1 ]; then pass=$((pass+1)); echo "PASS  $name"; else
    fail=$((fail+1)); echo "FAIL  $name  (got: $decisionv, want: $want) $out"
  fi
}

# ===========================================================================
# Vector 1 — Cross-segment carried profile: frozen account via exported env
# Class: policy evasion (frozen-profile mutation hidden by shell state)
# ===========================================================================

# Exported frozen profile in an earlier segment must reach a later mutation.
run_case "cross-segment: exported frozen profile then unstamped terminate" \
  "export AWS_PROFILE=legacy-frozen; AWS_SDK_UA_APP_ID=xx-x aws ec2 terminate-instances --instance-ids i-1" deny "FROZEN"

# A bare assignment segment (no export) also persists in the shell.
run_case "cross-segment: bare frozen assignment then delete carries forward" \
  "AWS_PROFILE=legacy-frozen; AWS_SDK_UA_APP_ID=xx-x aws rds delete-db-instance --db-instance-identifier db1" deny "FROZEN"

# A carried profile must never grant the personal-profile stamp exemption.
run_case "cross-segment: carried personal profile does not waive the stamp" \
  "export AWS_PROFILE=hobby; aws s3 cp ./site.html s3://my-hobby-site/" deny "purpose stamp"

# ===========================================================================
# Vector 2 — aws nested in command substitution ($() and backticks)
# Class: hidden-invocation (mutation smuggled inside a quoted argument)
# ===========================================================================

# Mutation hidden inside a quoted $() must still be classified and denied.
run_case "nested \$(): unstamped terminate inside a quoted filter value" \
  'AWS_SDK_UA_APP_ID=xx-scan aws ec2 describe-instances --filters "Name=x,Values=$(aws ec2 terminate-instances --instance-ids i-1)" --profile acct-read' deny "purpose stamp"

# Backtick substitution is the same evasion in older syntax.
run_case "nested backticks: unstamped terminate inside backticks" \
  'AWS_SDK_UA_APP_ID=xx-x aws s3 ls `aws ec2 terminate-instances --instance-ids i-1`' deny "purpose stamp"

# Two levels deep: a mutation buried in $( ... $( aws ... ) ... ) is reached
# because the extractor scans the whole text for every substitution opener.
run_case "nested \$() two levels deep: unstamped delete-volume at the bottom" \
  'AWS_SDK_UA_APP_ID=xx-outer aws ec2 describe-instances --filters "Name=t,Values=$(echo $(aws ec2 delete-volume --volume-id vol-9))" --profile acct-read' deny "purpose stamp"

# ===========================================================================
# Vector 3 — Parameters/skeleton sourced from a file the gate cannot read
# Class: opaque-input (real intent hidden behind file://)
# ===========================================================================

# --cli-input-json file:// on a mutation: the gate cannot inspect the file.
run_case "opaque input: run-instances --cli-input-json file:// asks" \
  "AWS_SDK_UA_APP_ID=xx-launch aws ec2 run-instances --cli-input-json file://params.json --profile acct-admin" ask "cannot inspect"

# --cli-input-yaml file:// is the same vector in YAML.
run_case "opaque input: put-parameter --cli-input-yaml file:// asks" \
  "AWS_SDK_UA_APP_ID=xx-cfg aws ssm put-parameter --cli-input-yaml file://param.yaml --profile acct-admin" ask "cannot inspect"

# ===========================================================================
# Vector 4 — Mass mutation via loop/batch constructs beyond for/while/xargs
# Class: unbounded-blast-radius (one command mutating many resources)
# ===========================================================================

# find -exec fanning a mutation across matched files.
run_case "mass mutation: find -exec aws s3 rm denied" \
  'find . -name "*.txt" -exec aws s3 rm s3://bucket/{} \;' deny "loop"

# GNU parallel fanning a destructive verb across piped input.
run_case "mass mutation: parallel aws ec2 delete-volume denied" \
  "echo vol-1 vol-2 | parallel AWS_SDK_UA_APP_ID=xx-x aws ec2 delete-volume --volume-id {}" deny "loop"

# ===========================================================================
# Vector 5 — Public-principal grants (world exposure without --acl shorthand)
# Class: exposure-boundary (grant to AllUsers / AuthenticatedUsers)
# ===========================================================================

# --grant-read to the AllUsers group URI opens the object to the world.
run_case "public grant: put-object-acl --grant-read AllUsers asks" \
  "AWS_SDK_UA_APP_ID=xx-share aws s3api put-object-acl --bucket b --key k --grant-read uri=http://acs.amazonaws.com/groups/global/AllUsers --profile acct-admin" ask "AllUsers"

# --grant-full-control to AuthenticatedUsers is the same exposure class.
run_case "public grant: put-bucket-acl --grant-full-control AuthenticatedUsers asks" \
  "AWS_SDK_UA_APP_ID=xx-share aws s3api put-bucket-acl --bucket b --grant-full-control uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers --profile acct-admin" ask "public principal group"

# ===========================================================================
# Vector 6 — Policy/trust body sourced from a file (wildcard principal risk)
# Class: opaque-policy (Principal "*" could hide in an unreadable file)
# ===========================================================================

# Resource policy body from file:// on a bucket-policy write.
run_case "opaque policy: put-bucket-policy --policy file:// asks about wildcard" \
  "AWS_SDK_UA_APP_ID=xx-policy aws s3api put-bucket-policy --bucket b --policy file://p.json --profile acct-admin" ask "wildcard"

# Trust policy body from file:// on role creation.
run_case "opaque policy: create-role trust-policy file:// asks about wildcard" \
  "AWS_SDK_UA_APP_ID=xx-role aws iam create-role --role-name r --assume-role-policy-document file://trust.json --tags Key=team,Value=example-team --profile acct-admin" ask "wildcard"

# ===========================================================================
# Vector 7 — Separator-broken brand markers in the purpose stamp
# Class: attribution-evasion (tool name split so word-boundary pass misses it)
# ===========================================================================

# Hyphen-broken brand token: xx-c-l-a-u-d-e-run.
run_case "attribution: hyphen-broken brand marker in stamp denied" \
  "AWS_SDK_UA_APP_ID=xx-c-l-a-u-d-e-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "marker"

# Underscore-broken brand token: xx-open_ai-sync.
run_case "attribution: underscore-broken brand marker in stamp denied" \
  "AWS_SDK_UA_APP_ID=xx-open_ai-sync aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "marker"

# ===========================================================================
# Vector 8 — Invisible-character-obfuscated brand markers in the stamp
# Class: attribution-evasion (zero-width / soft-hyphen splitting a tool name)
# ===========================================================================

# Soft hyphen (U+00AD) inside "claude": renders invisibly, splits the token.
run_case "attribution: soft-hyphen-obfuscated brand marker denied" \
  "$(printf 'AWS_SDK_UA_APP_ID=xx-clau\xc2\xadde-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin')" deny "marker"

# Zero-width space (U+200B) inside "openai": same evasion, different codepoint.
run_case "attribution: zero-width-space-obfuscated brand marker denied" \
  "$(printf 'AWS_SDK_UA_APP_ID=xx-open\xe2\x80\x8bai-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin')" deny "marker"

# ===========================================================================
# Vector 9 — Path-qualified CLI invocation (bypassing a bare-"aws" match)
# Class: invocation-obfuscation (/usr/bin/aws, ./aws must still be the gate's)
# ===========================================================================

# Absolute-path aws on a frozen account must still hit the frozen check.
run_case "path-qualified: /usr/bin/aws frozen terminate denied" \
  "export AWS_PROFILE=legacy-frozen; /usr/bin/aws ec2 terminate-instances --instance-ids i-1" deny "FROZEN"

# Absolute-path aws unstamped mutation must still require a stamp.
run_case "path-qualified: /usr/bin/aws unstamped delete-volume denied" \
  "/usr/bin/aws ec2 delete-volume --volume-id vol-1 --profile acct-admin" deny "purpose stamp"

# Relative-path ./aws unstamped mutation must still require a stamp.
run_case "path-qualified: ./aws unstamped delete-volume denied" \
  "./aws ec2 delete-volume --volume-id vol-1 --profile acct-admin" deny "purpose stamp"

# Path-qualified aws AllUsers grant must still surface as an exposure.
run_case "path-qualified: /usr/bin/aws AllUsers grant asks" \
  "AWS_SDK_UA_APP_ID=xx-share /usr/bin/aws s3api put-object-acl --bucket b --key k --grant-read uri=http://acs.amazonaws.com/groups/global/AllUsers --profile acct-admin" ask "AllUsers"

# ===========================================================================
# Benign lookalikes — must STAY ALLOWED (the gate never blocks honest work).
# Each mirrors a vector above closely enough to be a false-positive trap.
# ===========================================================================

# An s3 object key that merely ends in /aws is not a CLI invocation.
run_case "benign: s3 key ending in /aws stays allowed" \
  "aws s3 cp ./f.txt s3://bucket/path/aws --profile hobby" allow

# "claudia" contains the letters of a brand but is an ordinary name.
run_case "benign: claudia in the stamp stays allowed" \
  "AWS_SDK_UA_APP_ID=xx-claudia-migration aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" allow

# A tag value containing the word ' for ' must not trip the loop detector.
run_case "benign: tag value containing ' for ' stays allowed" \
  "AWS_SDK_UA_APP_ID=xx-tags aws elbv2 add-tags --resource-arns arn:x --tags 'Key=purpose,Value=Egress allowlist for the corporate boundary' --profile acct-admin" allow

# A benign read nested in $() (the same substitution mechanic as Vector 2).
run_case "benign: read-only \$() substitution stays allowed" \
  'aws ec2 describe-instances --filters "Name=tag:owner,Values=$(aws sts get-caller-identity --query Account --output text --profile acct-read)" --profile acct-read' allow

# AllUsers as a plain object key is not a grant to the AllUsers group.
run_case "benign: AllUsers as an object key stays allowed" \
  "AWS_SDK_UA_APP_ID=xx-up aws s3 cp ./AllUsers.csv s3://bucket/data/AllUsers.csv --profile acct-admin" allow

# --policy-arn / --policy-name reference a policy by identity, not a file body.
run_case "benign: get-policy --policy-arn stays allowed" \
  "aws iam get-policy --policy-arn arn:aws:iam::111111111111:policy/ExampleReadOnly --profile acct-read" allow

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
