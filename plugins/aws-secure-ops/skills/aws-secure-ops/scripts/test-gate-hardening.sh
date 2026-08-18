#!/usr/bin/env bash
# Hardening tests for classify-aws-command.py. A superset of
# test-classify-aws-command.sh: all 24 original cases verbatim, plus one case
# per closed evasion hole and a benign counterpart for each, plus ledger
# contract checks. Fully offline: no AWS calls, no credentials, throwaway
# policy and ledger files. Exit 0 when every case passes.
set -u

GATE="$(cd "$(dirname "$0")" && pwd)/classify-aws-command.py"
POLICY="$(mktemp)"
LEDGER="$(mktemp)"
POLICY_NOLEDGER="$(mktemp)"
LEDGER_OFF="$(mktemp -u)"
trap 'rm -f "$POLICY" "$LEDGER" "$POLICY_NOLEDGER" "$LEDGER_OFF"' EXIT
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
cat > "$POLICY_NOLEDGER" <<'EOF'
{
  "operator": { "name": "test-operator", "stamp_prefix": "xx" },
  "profiles": { "acct-read": "readonly" },
  "ledger": false
}
EOF
export AWS_OPS_POLICY_FILE="$POLICY"
export AWS_OPS_LEDGER_FILE="$LEDGER"
export PYTHONUTF8=1  # so invisible-character stamp cases round-trip through argv

pass=0; fail=0

run_case() { # name command expected(allow|deny|ask) [reason-substring]
  local name="$1" cmd="$2" want="$3" substr="${4:-}"
  local out decisionv
  out=$(printf '%s' "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")}}" | python3 "$GATE" 2>&1)
  if [ -z "$out" ]; then decisionv="allow"; else
    decisionv=$(printf '%s' "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])' 2>/dev/null || echo "parse-error")
  fi
  local ok=1
  [ "$decisionv" = "$want" ] || ok=0
  if [ -n "$substr" ] && ! printf '%s' "$out" | grep -qi "$substr"; then ok=0; fi
  if [ $ok -eq 1 ]; then pass=$((pass+1)); echo "PASS  $name"; else
    fail=$((fail+1)); echo "FAIL  $name  (got: $decisionv) $out"
  fi
}

# ---------------------------------------------------------------------------
# Original 24 cases, verbatim: the hardened gate must preserve every decision.
# ---------------------------------------------------------------------------

run_case "non-aws command passes" \
  "ls -la /tmp" allow

run_case "pointed read passes silently" \
  "AWS_SDK_UA_APP_ID=xx-check aws ec2 describe-volumes --volume-ids vol-0abc --profile acct-read" allow

run_case "unstamped read passes (stamp required only for mutations)" \
  "aws sts get-caller-identity --profile acct-read" allow

run_case "unstamped mutation denied" \
  "aws ec2 create-tags --resources vol-0abc --tags Key=env,Value=prod --profile acct-admin" deny "purpose stamp"

run_case "stamped modify passes" \
  "AWS_SDK_UA_APP_ID=xx-tag-fix aws ec2 create-tags --resources vol-0abc --tags Key=env,Value=prod --profile acct-admin" allow

run_case "stamped destroy asks for confirmation" \
  "AWS_SDK_UA_APP_ID=xx-cleanup aws ec2 delete-volume --volume-id vol-0abc --profile acct-admin" ask "Destructive"

run_case "frozen profile mutation denied" \
  "AWS_SDK_UA_APP_ID=xx-x aws ec2 delete-volume --volume-id vol-0abc --profile legacy-frozen" deny "FROZEN"

run_case "frozen profile read passes" \
  "AWS_SDK_UA_APP_ID=xx-audit aws ec2 describe-volumes --profile legacy-frozen" allow

run_case "loop over destructive verb denied" \
  "for v in vol-1 vol-2; do AWS_SDK_UA_APP_ID=xx-x aws ec2 delete-volume --volume-id \$v --profile acct-admin; done" deny "loop"

run_case "xargs into mutation denied" \
  "aws ec2 describe-volumes --query 'Volumes[].VolumeId' --output text --profile acct-read | xargs -n1 aws ec2 delete-volume --profile acct-admin --volume-id" deny "loop"

run_case "tool marker in tag value denied" \
  "AWS_SDK_UA_APP_ID=xx-x aws ec2 create-tags --resources i-1 --tags Key=owner,Value=claude --profile acct-admin" deny "marker"

run_case "tool marker in stamp denied" \
  "AWS_SDK_UA_APP_ID=xx-assistant-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "marker"

run_case "wrong stamp prefix denied" \
  "AWS_SDK_UA_APP_ID=zz-thing aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "prefix"

run_case "secret-material read asks" \
  "AWS_SDK_UA_APP_ID=xx-rotate aws secretsmanager get-secret-value --secret-id app/db --profile acct-admin" ask "secret"

run_case "tls verification bypass denied" \
  "aws s3 ls --no-verify-ssl" deny "TLS"

run_case "s3 sync --delete escalates to ask" \
  "AWS_SDK_UA_APP_ID=xx-publish aws s3 sync ./dist s3://bucket/app --delete --profile acct-admin" ask "Destructive"

run_case "purpose text containing ' for ' does not trip loop detector" \
  "AWS_SDK_UA_APP_ID=xx-tags aws elbv2 add-tags --resource-arns arn:x --tags 'Key=purpose,Value=Egress allowlist for the corporate boundary' --profile acct-admin" allow

run_case "non-aws endpoint asks" \
  "AWS_SDK_UA_APP_ID=xx-x aws s3api list-buckets --endpoint-url https://mirror.example.net --profile acct-read" ask "endpoint"

run_case "localhost endpoint passes" \
  "AWS_SDK_UA_APP_ID=xx-x aws s3api list-buckets --endpoint-url http://localhost:4566 --profile acct-read" allow

run_case "untagged create asks" \
  "AWS_SDK_UA_APP_ID=xx-restore aws ec2 create-volume --size 10 --availability-zone az-1 --profile acct-admin" ask "without tags"

run_case "second unstamped segment in a chain denied" \
  "AWS_SDK_UA_APP_ID=xx-x aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin && aws ec2 delete-volume --volume-id vol-1 --profile acct-admin" deny "purpose stamp"

run_case "personal profile mutation exempt from stamp" \
  "aws s3 cp ./site.html s3://my-hobby-site/ --profile hobby" allow

run_case "aws help passes" \
  "aws help" allow

run_case "cloudformation change-set chain passes when stamped" \
  "AWS_SDK_UA_APP_ID=xx-deploy aws cloudformation create-change-set --stack-name s --change-set-name c --template-body file://t.yml --tags Key=team,Value=example-team --profile acct-admin && AWS_SDK_UA_APP_ID=xx-deploy aws cloudformation wait change-set-create-complete --stack-name s --change-set-name c --profile acct-admin" allow

# AWS CLI uses argparse long-option abbreviations. The gate must canonicalize
# unique global prefixes exactly as the CLI does, including flags before the
# service, while preserving ambiguous prefixes as invalid/no-op gate input.
run_case "abbreviated TLS bypass is denied" \
  "aws s3 ls --no-v" deny "TLS"

run_case "abbreviated external endpoint asks" \
  "aws s3api list-buckets --endpoint-u https://mirror.example.net --p acct-read" ask "endpoint"

run_case "inline abbreviated external endpoint asks" \
  "aws --e=https://mirror.example.net s3api list-buckets --p=acct-read" ask "endpoint"

run_case "abbreviated localhost endpoint preserves allow" \
  "aws s3api list-buckets --e http://localhost:4566 --p acct-read" allow

run_case "abbreviated frozen profile still denies mutation" \
  "AWS_SDK_UA_APP_ID=xx-x aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --p legacy-frozen" deny "FROZEN"

run_case "abbreviated CA and globals before service parse correctly" \
  "aws --ca /tmp/corp-ca.pem --r us-east-1 --o json sts get-caller-identity --p acct-read" allow

run_case "CLI error format before service parses correctly" \
  "aws --cli-error-format json sts get-caller-identity --profile acct-read" allow

run_case "ambiguous global abbreviation is not misclassified as TLS" \
  "aws s3 ls --no" allow

run_case "abbreviated s3 sync delete escalates to ask" \
  "AWS_SDK_UA_APP_ID=xx-publish aws s3 sync ./dist s3://bucket/app --del --profile acct-admin" ask "Destructive"

run_case "SSO logout is a disruptive local mutation" \
  "AWS_SDK_UA_APP_ID=xx-logout aws sso logout --profile acct-admin" ask "Destructive"

run_case "logs tail follow is denied as unbounded" \
  "aws logs tail /aws/example --follow --profile acct-read" deny "Unbounded"

run_case "abbreviated logs tail follow is denied" \
  "aws logs tail /aws/example --fol --profile acct-read" deny "Unbounded"

# ---------------------------------------------------------------------------
# Hole 1 — cross-segment AWS_PROFILE tracking
# ---------------------------------------------------------------------------

run_case "exported frozen profile in earlier segment denied" \
  "export AWS_PROFILE=legacy-frozen; AWS_SDK_UA_APP_ID=xx-x aws ec2 delete-volume --volume-id vol-1" deny "FROZEN"

run_case "bare frozen assignment segment carries forward (deny)" \
  "AWS_PROFILE=legacy-frozen; AWS_SDK_UA_APP_ID=xx-x aws rds delete-db-instance --db-instance-identifier db1" deny "FROZEN"

run_case "exported readonly profile read still passes" \
  "export AWS_PROFILE=acct-read; aws sts get-caller-identity" allow

run_case "explicit --profile overrides carried frozen profile" \
  "export AWS_PROFILE=legacy-frozen; AWS_SDK_UA_APP_ID=xx-fix aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" allow

run_case "carried personal profile does not waive the stamp rule" \
  "export AWS_PROFILE=hobby; aws s3 cp ./site.html s3://my-hobby-site/" deny "purpose stamp"

run_case "unset clears a carried frozen profile" \
  "export AWS_PROFILE=legacy-frozen; unset AWS_PROFILE; AWS_SDK_UA_APP_ID=xx-fix aws ec2 create-tags --resources i-1 --tags Key=a,Value=b" allow

# ---------------------------------------------------------------------------
# Hole 2 — aws invocations nested in command substitution
# ---------------------------------------------------------------------------

run_case "unstamped mutation hidden in quoted \$() denied" \
  'AWS_SDK_UA_APP_ID=xx-scan aws ec2 describe-instances --filters "Name=x,Values=$(aws ec2 terminate-instances --instance-ids i-1)" --profile acct-read' deny "purpose stamp"

run_case "unstamped mutation hidden in backticks denied" \
  'AWS_SDK_UA_APP_ID=xx-x aws s3 ls `aws ec2 terminate-instances --instance-ids i-1`' deny "purpose stamp"

run_case "stamped destroy inside quoted \$() still surfaces (ask)" \
  'aws logs filter-log-events --log-group-name "/app/$(AWS_SDK_UA_APP_ID=xx-clean aws ec2 delete-volume --volume-id vol-9 --profile acct-admin)" --profile acct-read' ask "Destructive"

run_case "benign read inside quoted \$() passes" \
  'aws ec2 describe-instances --filters "Name=tag:owner,Values=$(aws sts get-caller-identity --query Account --output text --profile acct-read)" --profile acct-read' allow

# ---------------------------------------------------------------------------
# Hole 3 — --cli-input-json/--cli-input-yaml file:// on a mutation
# ---------------------------------------------------------------------------

run_case "mutating cli-input-json from file asks" \
  "AWS_SDK_UA_APP_ID=xx-launch aws ec2 run-instances --cli-input-json file://params.json --profile acct-admin" ask "cannot inspect"

run_case "mutating cli-input-yaml from file asks" \
  "AWS_SDK_UA_APP_ID=xx-cfg aws ssm put-parameter --cli-input-yaml file://param.yaml --profile acct-admin" ask "cannot inspect"

run_case "read with cli-input-json from file still passes" \
  "aws ec2 describe-instances --cli-input-json file://query.json --profile acct-read" allow

# ---------------------------------------------------------------------------
# Hole 4 — find -exec and parallel join the loop/batch detector
# ---------------------------------------------------------------------------

run_case "find -exec into aws mutation denied" \
  'find . -name "*.txt" -exec aws s3 rm s3://bucket/{} \;' deny "loop"

run_case "parallel into aws mutation denied" \
  "echo vol-1 vol-2 | parallel AWS_SDK_UA_APP_ID=xx-x aws ec2 delete-volume --volume-id {}" deny "loop"

run_case "find -exec without aws passes untouched" \
  'find . -name "*.log" -exec rm {} \;' allow

run_case "find -exec then separate stamped aws copy passes" \
  'find /tmp -name "*.bak" -exec rm {} \; ; AWS_SDK_UA_APP_ID=xx-upload aws s3 cp ./report.pdf s3://bucket/reports/ --profile acct-admin' allow

# ---------------------------------------------------------------------------
# Hole 5 — public exposure via grant flags / group URIs
# ---------------------------------------------------------------------------

run_case "grant-read to AllUsers group uri asks" \
  "AWS_SDK_UA_APP_ID=xx-share aws s3api put-object-acl --bucket b --key k --grant-read uri=http://acs.amazonaws.com/groups/global/AllUsers --profile acct-admin" ask "AllUsers"

run_case "grant-full-control to AuthenticatedUsers asks" \
  "AWS_SDK_UA_APP_ID=xx-share aws s3api put-bucket-acl --bucket b --grant-full-control uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers --profile acct-admin" ask "public principal group"

run_case "AllUsers as a mere object key does not trip the grant check" \
  "AWS_SDK_UA_APP_ID=xx-up aws s3 cp ./AllUsers.csv s3://bucket/data/AllUsers.csv --profile acct-admin" allow

run_case "AllUsers in a log-group name on a read passes" \
  "aws logs filter-log-events --log-group-name /app/AllUsers-audit --profile acct-read" allow

# ---------------------------------------------------------------------------
# Hole 6 — policy body sourced from a file the gate cannot read
# ---------------------------------------------------------------------------

run_case "put-bucket-policy from file asks about wildcard principals" \
  "AWS_SDK_UA_APP_ID=xx-policy aws s3api put-bucket-policy --bucket b --policy file://p.json --profile acct-admin" ask "wildcard"

run_case "create-role trust policy from file asks about wildcard principals" \
  "AWS_SDK_UA_APP_ID=xx-role aws iam create-role --role-name r --assume-role-policy-document file://trust.json --tags Key=team,Value=example-team --profile acct-admin" ask "wildcard"

run_case "policy referenced by --policy-arn does not trip the file check" \
  "aws iam get-policy --policy-arn arn:aws:iam::111111111111:policy/ExampleReadOnly --profile acct-read" allow

run_case "read with --policy-name does not trip the file check" \
  "aws iam get-role-policy --role-name r --policy-name p --profile acct-read" allow

# ---------------------------------------------------------------------------
# Hole 7 — separator-obfuscated brand markers in the purpose stamp
# ---------------------------------------------------------------------------

run_case "separator-broken brand marker in stamp denied" \
  "AWS_SDK_UA_APP_ID=xx-c-l-a-u-d-e-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "marker"

run_case "underscore-obfuscated brand marker in stamp denied" \
  "AWS_SDK_UA_APP_ID=xx-open_ai-sync aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" deny "marker"

run_case "ordinary name resembling a brand passes (claudia)" \
  "AWS_SDK_UA_APP_ID=xx-claudia-migration aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" allow

run_case "normal slug with dots and underscores passes" \
  "AWS_SDK_UA_APP_ID=xx-db.backup_check aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin" allow

# ---------------------------------------------------------------------------
# Hole 8 — missing/corrupt policy residual (documented, gate stays robust)
# ---------------------------------------------------------------------------

SAVED_POLICY="$AWS_OPS_POLICY_FILE"
export AWS_OPS_POLICY_FILE="/nonexistent-aws-ops-policy-$$.json"
run_case "missing policy: unstamped mutation still denied" \
  "aws ec2 delete-volume --volume-id vol-1" deny "purpose stamp"
run_case "missing policy: stamped mutation passes (documented residual)" \
  "AWS_SDK_UA_APP_ID=zz-anything aws ec2 create-tags --resources i-1 --tags Key=a,Value=b" allow
export AWS_OPS_POLICY_FILE="$SAVED_POLICY"

# ---------------------------------------------------------------------------
# Path-qualified CLI invocation must not bypass the gate (RT1 critical)
# ---------------------------------------------------------------------------

run_case "absolute-path aws frozen mutation denied" \
  "export AWS_PROFILE=legacy-frozen; /usr/bin/aws ec2 terminate-instances --instance-ids i-1" deny "FROZEN"

run_case "absolute-path aws unstamped mutation denied" \
  "/usr/bin/aws ec2 delete-volume --volume-id vol-1 --profile acct-admin" deny "purpose stamp"

run_case "relative-path aws unstamped mutation denied" \
  "./aws ec2 delete-volume --volume-id vol-1 --profile acct-admin" deny "purpose stamp"

run_case "path aws AllUsers grant asks" \
  "AWS_SDK_UA_APP_ID=xx-share /usr/bin/aws s3api put-object-acl --bucket b --key k --grant-read uri=http://acs.amazonaws.com/groups/global/AllUsers --profile acct-admin" ask "AllUsers"

run_case "path aws pointed read passes" \
  "AWS_SDK_UA_APP_ID=xx-check /usr/local/bin/aws ec2 describe-volumes --volume-ids vol-0abc --profile acct-read" allow

run_case "s3 key ending in /aws is not treated as an invocation" \
  "aws s3 cp ./f.txt s3://bucket/path/aws --profile hobby" allow

# ---------------------------------------------------------------------------
# Invisible-character-obfuscated brand marker in the stamp (RT1 medium)
# ---------------------------------------------------------------------------

run_case "soft-hyphen-obfuscated brand marker in stamp denied" \
  "$(printf 'AWS_SDK_UA_APP_ID=xx-clau\xc2\xadde-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin')" deny "marker"

run_case "zero-width-obfuscated brand marker in stamp denied" \
  "$(printf 'AWS_SDK_UA_APP_ID=xx-open\xe2\x80\x8bai-run aws ec2 create-tags --resources i-1 --tags Key=a,Value=b --profile acct-admin')" deny "marker"

# ---------------------------------------------------------------------------
# Ledger contract
# ---------------------------------------------------------------------------

# Every inspected invocation above should have produced exactly one metadata
# line; validate shape, key order, decisions, and the privacy rule (no raw
# command text, argument values, or tag values).
if python3 - "$LEDGER" <<'EOF'
import json, sys
from datetime import datetime

path = sys.argv[1]
keys = ["ts", "service", "operation", "class", "sensitive", "decision",
        "stamp", "profile", "profile_class"]
raw = open(path, encoding="utf-8").read()
lines = [l for l in raw.splitlines() if l.strip()]
assert lines, "ledger is empty"
decisions = set()
for line in lines:
    pairs = json.loads(line, object_pairs_hook=lambda p: p)
    assert [k for k, _ in pairs] == keys, f"bad key order: {pairs}"
    rec = dict(pairs)
    datetime.fromisoformat(rec["ts"])
    assert rec["decision"] in ("allow", "ask", "deny"), rec
    assert isinstance(rec["sensitive"], bool), rec
    decisions.add(rec["decision"])
assert {"allow", "ask", "deny"} <= decisions, f"missing decisions: {decisions}"
# Privacy: no argument values, resource ids, tag values, or flags.
for forbidden in ("vol-0abc", "--profile", "s3://", "file://", "Key=",
                  "volume-id", "i-1", "AllUsers"):
    assert forbidden not in raw, f"raw command material leaked: {forbidden}"
print(f"ledger ok: {len(lines)} lines")
EOF
then pass=$((pass+1)); echo "PASS  ledger lines have the exact contract shape"; else
  fail=$((fail+1)); echo "FAIL  ledger lines have the exact contract shape"
fi

# Ledger disabled by policy: no line may be written.
SAVED_POLICY="$AWS_OPS_POLICY_FILE"; SAVED_LEDGER="$AWS_OPS_LEDGER_FILE"
export AWS_OPS_POLICY_FILE="$POLICY_NOLEDGER"
export AWS_OPS_LEDGER_FILE="$LEDGER_OFF"
run_case "ledger disabled by policy: decision unchanged" \
  "aws sts get-caller-identity --profile acct-read" allow
if [ ! -s "$LEDGER_OFF" ]; then pass=$((pass+1)); echo "PASS  ledger disabled by policy writes nothing"; else
  fail=$((fail+1)); echo "FAIL  ledger disabled by policy writes nothing"
fi
export AWS_OPS_POLICY_FILE="$SAVED_POLICY"

# Unwritable ledger path: best-effort only, the decision must not change.
export AWS_OPS_LEDGER_FILE="/nonexistent-dir-$$/ledger.jsonl"
run_case "unwritable ledger path never changes the decision" \
  "AWS_SDK_UA_APP_ID=xx-check aws ec2 describe-volumes --volume-ids vol-0abc --profile acct-read" allow
export AWS_OPS_LEDGER_FILE="$SAVED_LEDGER"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
