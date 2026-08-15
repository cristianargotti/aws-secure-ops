#!/usr/bin/env bash
# Unit tests for classify-aws-command.py. Fully offline: no AWS calls, no
# credentials, a throwaway policy file. Exit 0 when every case passes.
set -u

GATE="$(cd "$(dirname "$0")" && pwd)/classify-aws-command.py"
POLICY="$(mktemp)"
LEDGER="$(mktemp)"
trap 'rm -f "$POLICY" "$LEDGER"' EXIT
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
export AWS_OPS_POLICY_FILE="$POLICY"
export AWS_OPS_LEDGER_FILE="$LEDGER"

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

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
