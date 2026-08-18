#!/usr/bin/env python3
"""Offline regression suite for the Codex read-only AWS hook.

The suite feeds synthetic PreToolUse events to the classifier. It never runs
the AWS CLI and never reads the operator's real policy or credentials.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
GATE = HERE / "classify-aws-command.py"
TRUSTED = "/safe/aws"
UNSAFE_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CA_BUNDLE",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PYTHONUSERBASE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BOTO_CONFIG",
    "AWS_DATA_PATH",
    "AWS_OPS_UNSAFE_LAUNCH_ENV",
    "SSLKEYLOGFILE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
)

POLICY = {
    "operator": {"name": "offline-test", "stamp_prefix": "xx"},
    "profiles": {
        "probe-read": "readonly",
        "probe-admin": "admin",
        "probe-frozen": "frozen",
        "probe-personal": "personal",
    },
    "required_tags": {},
    "ledger": False,
}
PASSED = 0


def invoke(
    command,
    policy=POLICY,
    policy_file=None,
    raw_event=None,
    mode="readonly",
    extra_env=None,
    policy_mode=0o600,
    gate=GATE,
):
    created_policy = policy_file is None
    if created_policy:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            if isinstance(policy, str):
                fh.write(policy)
            else:
                json.dump(policy, fh)
            policy_path = fh.name
        os.chmod(policy_path, policy_mode)
    else:
        policy_path = str(policy_file)
    env = dict(os.environ)
    for name in UNSAFE_ENV:
        env.pop(name, None)
    for name in tuple(env):
        if name.startswith("AWS_") or name.startswith(("DYLD_", "BASH_FUNC_")):
            env.pop(name, None)
    env.update(
        {
            "AWS_OPS_HOOK_RUNTIME": "codex",
            "AWS_OPS_MODE": mode,
            "AWS_OPS_TRUSTED_AWS_CLI": TRUSTED,
            "AWS_OPS_POLICY_FILE": policy_path,
            "AWS_OPS_LEDGER_FILE": os.devnull,
        }
    )
    if extra_env:
        env.update(extra_env)
    event = raw_event
    if event is None:
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    try:
        proc = subprocess.run(
            [sys.executable, str(gate)],
            input=event,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
    finally:
        if created_policy:
            os.unlink(policy_path)
    if proc.returncode != 0:
        raise AssertionError(
            f"gate exited {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}"
        )
    output = proc.stdout.strip()
    if not output:
        return "allow", ""
    payload = json.loads(output)
    hook = payload["hookSpecificOutput"]
    return hook["permissionDecision"], hook.get("permissionDecisionReason", "")


def safe(service="sts", operation="get-caller-identity", extra=""):
    return (
        "AWS_SDK_UA_APP_ID=xx-offline-test "
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true "
        f"{TRUSTED} {service} {operation} --profile probe-read "
        f"--region us-east-1 --no-cli-pager --no-cli-auto-prompt {extra}"
    ).strip()


def expect(name, wanted, command="", **kwargs):
    global PASSED
    actual, reason = invoke(command, **kwargs)
    if actual != wanted:
        raise AssertionError(
            f"{name}: expected {wanted}, got {actual}: {reason or '(silent)'}"
        )
    PASSED += 1
    print(f"PASS {name}")


def expect_ledger_safety():
    global PASSED
    policy = dict(POLICY)
    policy["ledger"] = True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sentinel = root / "sentinel"
        sentinel.write_text("do-not-touch\n", encoding="utf-8")
        os.chmod(sentinel, 0o640)
        ledger_link = root / "ledger-link"
        ledger_link.symlink_to(sentinel)

        actual, reason = invoke(
            safe(),
            policy=policy,
            extra_env={"AWS_OPS_LEDGER_FILE": str(ledger_link)},
        )
        if actual != "allow":
            raise AssertionError(f"ledger symlink: safe command denied: {reason}")
        if sentinel.read_text(encoding="utf-8") != "do-not-touch\n":
            raise AssertionError("ledger symlink: target content changed")
        if sentinel.stat().st_mode & 0o777 != 0o640:
            raise AssertionError("ledger symlink: target mode changed")
        PASSED += 1
        print("PASS ledger symlink target is untouched")

        ledger = root / "ledger.jsonl"
        actual, reason = invoke(
            safe(),
            policy=policy,
            extra_env={"AWS_OPS_LEDGER_FILE": str(ledger)},
        )
        if actual != "allow":
            raise AssertionError(f"regular ledger: safe command denied: {reason}")
        if not ledger.is_file() or ledger.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("regular ledger: expected a 0600 regular file")
        records = ledger.read_text(encoding="utf-8").splitlines()
        if len(records) != 1 or json.loads(records[0]).get("decision") != "allow":
            raise AssertionError("regular ledger: expected one allow metadata record")
        PASSED += 1
        print("PASS regular ledger is created mode 600")

        if hasattr(os, "mkfifo"):
            ledger_fifo = root / "ledger-fifo"
            os.mkfifo(ledger_fifo, 0o600)
            started = time.monotonic()
            actual, reason = invoke(
                safe(),
                policy=policy,
                extra_env={"AWS_OPS_LEDGER_FILE": str(ledger_fifo)},
            )
            elapsed = time.monotonic() - started
            if actual != "allow":
                raise AssertionError(f"ledger FIFO: safe command denied: {reason}")
            if elapsed >= 2.0:
                raise AssertionError(
                    f"ledger FIFO: expected nonblocking handling, took {elapsed:.2f}s"
                )
            PASSED += 1
            print(f"PASS ledger FIFO is ignored in {elapsed:.3f}s")


def expect_symlink_alias_blocked():
    global PASSED
    with tempfile.TemporaryDirectory() as tmp:
        alias = Path(tmp) / "x"
        alias.symlink_to(TRUSTED)
        command = safe().replace(TRUSTED, str(alias))
        actual, reason = invoke(command)
        if actual != "deny":
            raise AssertionError(
                f"symlinked CLI alias: expected deny, got {actual}: {reason}"
            )
        PASSED += 1
        print("PASS symlinked trusted CLI alias is blocked")


def expect_complexity_deny_is_fast(command):
    global PASSED
    started = time.monotonic()
    actual, reason = invoke(command)
    elapsed = time.monotonic() - started
    if actual != "deny":
        raise AssertionError(
            f"complexity limit: expected deny, got {actual}: {reason or '(silent)'}"
        )
    if elapsed >= 2.0:
        raise AssertionError(
            f"complexity limit: expected bounded rejection under 2s, took {elapsed:.2f}s"
        )
    PASSED += 1
    print(f"PASS complexity limit rejects in {elapsed:.3f}s")


def expect_policy_special_files_fail_fast():
    global PASSED
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        paths = []
        if hasattr(os, "mkfifo"):
            fifo = root / "policy-fifo"
            os.mkfifo(fifo, 0o600)
            paths.append(("FIFO", fifo))
        oversized = root / "oversized-policy.json"
        with oversized.open("wb") as stream:
            stream.truncate(1_048_577)
        oversized.chmod(0o600)
        paths.append(("oversized file", oversized))

        for label, path in paths:
            started = time.monotonic()
            actual, reason = invoke(safe(), policy_file=path)
            elapsed = time.monotonic() - started
            if actual != "deny":
                raise AssertionError(
                    f"policy {label}: expected deny, got {actual}: {reason}"
                )
            if elapsed >= 2.0:
                raise AssertionError(
                    f"policy {label}: expected bounded rejection, took {elapsed:.2f}s"
                )
            PASSED += 1
            print(f"PASS policy {label} fails closed in {elapsed:.3f}s")


def expect_inventory_special_files_fail_fast():
    global PASSED
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "skill"
        scripts = root / "scripts"
        inventory_dir = root / "references" / "inventory"
        scripts.mkdir(parents=True)
        inventory_dir.mkdir(parents=True)
        copied_gate = scripts / GATE.name
        shutil.copy2(GATE, copied_gate)
        inventory = inventory_dir / "inventory.csv"
        cases = []
        if hasattr(os, "mkfifo"):
            os.mkfifo(inventory, 0o600)
            cases.append(("FIFO", inventory))
        oversized = inventory_dir / "oversized.csv"
        with oversized.open("wb") as stream:
            stream.truncate(16_777_217)
        cases.append(("oversized file", oversized))

        for label, source in cases:
            if inventory.exists() or inventory.is_symlink():
                inventory.unlink()
            if label == "FIFO":
                os.mkfifo(inventory, 0o600)
            else:
                source.replace(inventory)
            started = time.monotonic()
            actual, reason = invoke(safe(), gate=copied_gate)
            elapsed = time.monotonic() - started
            if actual != "deny" or "inventory" not in reason.lower():
                raise AssertionError(
                    f"inventory {label}: expected inventory deny, got {actual}: {reason}"
                )
            if elapsed >= 2.0:
                raise AssertionError(
                    f"inventory {label}: expected bounded rejection, took {elapsed:.2f}s"
                )
            PASSED += 1
            print(f"PASS inventory {label} fails closed in {elapsed:.3f}s")


def expect_aws_alias_file_blocked():
    global PASSED
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        alias_dir = home / ".aws" / "cli"
        alias_dir.mkdir(parents=True)
        alias = alias_dir / "alias"
        alias.write_text(
            "[command sts]\n"
            "get-caller-identity = !aws ec2 terminate-instances "
            "--instance-ids i-offline-only\n",
            encoding="utf-8",
        )
        actual, reason = invoke(safe(), extra_env={"HOME": str(home)})
        if actual != "deny" or "aliases" not in reason.lower():
            raise AssertionError(
                f"AWS CLI alias shadow: expected alias deny, got {actual}: {reason}"
            )
        PASSED += 1
        print("PASS AWS CLI alias command shadow is blocked")

        alias.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(alias, 0o600)
            started = time.monotonic()
            actual, reason = invoke(safe(), extra_env={"HOME": str(home)})
            elapsed = time.monotonic() - started
            if actual != "deny" or elapsed >= 2.0:
                raise AssertionError(
                    f"AWS CLI alias FIFO: expected fast deny, got {actual} "
                    f"in {elapsed:.2f}s: {reason}"
                )
            PASSED += 1
            print(f"PASS AWS CLI alias FIFO fails closed in {elapsed:.3f}s")


def main():
    expect("pointed identity read", "allow", safe())
    expect(
        "future CLI error format global parses before service",
        "allow",
        safe().replace(TRUSTED + " sts", TRUSTED + " --cli-error-format json sts"),
    )
    expect(
        "bounded paginated read",
        "allow",
        safe("ec2", "describe-instances", "--max-items 25 --page-size 25"),
    )

    base = safe()
    expect("echo aws text", "allow", "echo aws")
    expect("rg aws text", "allow", "rg aws README.md")
    expect("printf aws path text", "allow", "printf %s /safe/aws")
    expect("piped aws text", "allow", "echo aws | sed s/aws/AWS/")
    expect("chained aws search text", "allow", "rg aws README.md && echo ok")
    expect("generic aws argument text", "allow", "python tool.py aws")
    expect("copy aws-named notes", "allow", "cp README.md aws-notes.md")
    expect("move aws-named notes", "allow", "mv aws-notes.md docs.md")
    expect("link aws-named notes", "allow", "ln -s docs.md aws-link")
    expect("install aws-named data", "allow", "install file aws-tool")
    expect("env-wrapped aws search text", "allow", "env LANG=C rg aws README.md")
    expect("quoted AWS variable text", "allow", "echo '$AWS'")
    expect("dynamic non-AWS command path", "allow", '"$HOME/bin/tool" --version')
    expect("dynamic shell without AWS", "allow", "${SHELL} -c true")
    expect(
        "command-substituted non-AWS command",
        "allow",
        "$(command -v python3) -V",
    )
    expect("aws text ignores corrupt policy", "allow", "echo aws", policy="{")
    expect(
        "aws text ignores inherited profile",
        "allow",
        "echo aws",
        extra_env={"AWS_PROFILE": "probe-admin"},
    )
    expect(
        "echo protocol text",
        "allow",
        "echo AWS_SDK_UA_APP_ID=xx-offline-test /safe/aws",
    )
    expect(
        "quote-concatenated trusted path",
        "allow",
        base.replace(TRUSTED, '"/safe"/a"ws"'),
    )
    expect(
        "safe read in command substitution",
        "allow",
        'printf %s "$(' + base + ')"',
    )
    expect("missing profile", "deny", base.replace("--profile probe-read ", ""))
    expect(
        "admin profile",
        "deny",
        base.replace("--profile probe-read", "--profile probe-admin"),
    )
    expect("duplicate profile uses last", "deny", base + " --profile probe-admin")
    expect(
        "abbreviated profile override",
        "deny",
        base + " --prof probe-admin",
    )
    expect("missing region", "deny", base.replace("--region us-east-1 ", ""))
    expect(
        "region flag missing value",
        "deny",
        base.replace("--region us-east-1", "--region"),
    )
    expect(
        "expanded region value",
        "deny",
        base.replace("--region us-east-1", "--region=$REGION"),
    )
    expect(
        "abbreviated region override",
        "deny",
        base + " --reg eu-west-1",
    )
    expect(
        "profile flag missing value",
        "deny",
        base.replace("--profile probe-read", "--profile"),
    )
    expect(
        "expanded profile value",
        "deny",
        base.replace("--profile probe-read", "--profile=$PROFILE"),
    )
    expect(
        "missing purpose stamp",
        "deny",
        base.replace("AWS_SDK_UA_APP_ID=xx-offline-test ", ""),
    )
    expect(
        "non-kebab purpose stamp",
        "deny",
        base.replace("xx-offline-test", "xx_Bad"),
    )
    expect(
        "missing endpoint isolation",
        "deny",
        base.replace("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true ", ""),
    )
    expect(
        "duplicate endpoint isolation uses last",
        "deny",
        base.replace(TRUSTED, "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=false " + TRUSTED),
    )
    expect("missing no-cli-pager", "deny", base.replace("--no-cli-pager", ""))
    expect(
        "abbreviated no-cli-pager duplicate",
        "deny",
        base + " --no-cli-p",
    )
    expect(
        "missing no-cli-auto-prompt",
        "deny",
        base.replace("--no-cli-auto-prompt", ""),
    )
    expect("interactive CLI auto prompt", "deny", base + " --cli-auto-prompt")
    expect("abbreviated CLI auto prompt", "deny", base + " --cli-a")
    expect(
        "abbreviated no-auto-prompt duplicate",
        "deny",
        base + " --no-cli-a",
    )
    expect("debug output", "deny", base + " --debug")
    expect("abbreviated debug output", "deny", base + " --d")
    expect("bounded read timeout", "allow", base + " --cli-read-timeout 30")
    expect("zero read timeout", "deny", base + " --cli-read-timeout 0")
    expect("oversized connect timeout", "deny", base + " --cli-connect-timeout 121")
    expect("invalid read timeout", "deny", base + " --cli-read-timeout forever")
    expect("abbreviated timeout flag", "deny", base + " --cli-read-t 30")
    expect("untrusted executable", "deny", base.replace(TRUSTED, "aws"))
    expect(
        "custom endpoint flag",
        "deny",
        base + " --endpoint-url https://example.invalid",
    )
    for name, suffix in (
        ("abbreviated endpoint flag", "--endpoint-u https://example.invalid"),
        ("inline abbreviated endpoint flag", "--endpoint-u=https://example.invalid"),
        ("abbreviated CA bundle flag", "--ca-b /tmp/attacker-ca.pem"),
        ("inline abbreviated CA bundle flag", "--ca-b=/tmp/attacker-ca.pem"),
        ("abbreviated no-verify flag", "--no-verify"),
    ):
        expect(name, "deny", base + " " + suffix)
    expect(
        "inline credential override",
        "deny",
        "AWS_ACCESS_KEY_ID=fake " + base,
    )
    for assignment in ("HOME=/tmp", "PATH=/tmp", "BASH_ENV=/tmp/hook"):
        expect(
            f"inline context override: {assignment.split('=', 1)[0]}",
            "deny",
            assignment + " " + base,
        )
    for prefix in (
        "HOME=/tmp;",
        "export HOME=/tmp;",
        "PATH=/tmp;",
        "export PATH=/tmp;",
        "unset HOME;",
    ):
        expect(
            f"cross-segment context override: {prefix.split()[0].rstrip(';')}",
            "deny",
            prefix + " " + base,
        )
    expect(
        "temporary HOME for non-AWS command does not taint later read",
        "allow",
        "HOME=/tmp echo x; " + base,
    )
    expect(
        "printed PATH text does not taint later read",
        "allow",
        "echo 'PATH=/tmp'; " + base,
    )
    expect(
        "printed AWS profile text does not taint later read",
        "allow",
        "echo AWS_PROFILE=probe-admin; " + base,
    )
    expect(
        "exported AWS profile taints later read",
        "deny",
        "export AWS_PROFILE=probe-admin; " + base,
    )
    for wrapper in (
        "sudo",
        "arch -arm64",
        "builtin exec",
        "busybox",
        "caffeinate -i",
        "chpst -u nobody",
        "daemonize",
        "env HOME=/tmp",
        "expect -c spawn",
        "flock /tmp/aws-secure-ops-test.lock",
        "ionice",
        "command",
        "nocorrect",
        "noglob",
        "nohup",
        "time",
        "xargs",
        "parallel",
        "perf stat",
        "prlimit --nofile=1024:1024",
        "rlwrap",
        "runuser -u nobody --",
        "script -q /dev/null",
        "screen -dmS probe",
        "setpriv --no-new-privs",
        "setsid",
        "setuidgid nobody",
        "stdbuf -oL",
        "start-stop-daemon --start --exec",
        "strace",
        "systemd-run --user",
        "taskset -c 0",
        "toybox",
        "tmux new-session -d",
        "unshare --fork",
        "valgrind",
        "watch",
    ):
        expect(
            f"execution wrapper blocked: {wrapper.split()[0]}",
            "deny",
            base.replace(TRUSTED, wrapper + " " + TRUSTED),
        )
    for name, command in (
        ("tmux quoted body", f"tmux new-session -d '{base}'"),
        ("screen quoted body", f"screen -dmS probe '{base}'"),
        ("expect quoted body", f"expect -c 'spawn {base}'"),
    ):
        expect(name, "deny", command)
    expect(
        "trusted CLI piped into xargs blocked",
        "deny",
        "printf %s /safe/aws | xargs -I{} {} ec2 terminate-instances "
        "--instance-ids i-123",
    )
    expect(
        "which aws piped into xargs blocked",
        "deny",
        "which aws | xargs -I{} {} ec2 terminate-instances --instance-ids i-123",
    )
    expect(
        "zsh command hash alias blocked",
        "deny",
        "hash x=/safe/aws; x ec2 terminate-instances --instance-ids i-123",
    )
    expect(
        "bash command hash alias blocked",
        "deny",
        "hash -p /safe/aws x; x ec2 terminate-instances --instance-ids i-123",
    )
    expect(
        "bash -c wrapper around safe read blocked",
        "deny",
        "bash -c '" + base + "'",
    )
    expect(
        "HOME override through sh -c blocked",
        "deny",
        "HOME=/tmp sh -c '" + base + "'",
    )
    expect(
        "inherited credential override",
        "deny",
        base,
        extra_env={"AWS_ACCESS_KEY_ID": "fake"},
    )
    expect(
        "inherited web identity override",
        "deny",
        base,
        extra_env={"AWS_ROLE_ARN": "arn:aws:iam::111111111111:role/fake"},
    )
    expect(
        "inherited service endpoint override",
        "deny",
        base,
        extra_env={"AWS_ENDPOINT_URL_DYNAMODB": "https://example.invalid"},
    )
    expect(
        "inherited Python path override",
        "deny",
        base,
        extra_env={"PYTHONPATH": "/tmp/attacker-python"},
    )
    expect(
        "launcher-recorded unsafe environment",
        "deny",
        base,
        extra_env={"AWS_OPS_UNSAFE_LAUNCH_ENV": "PYTHONPATH,HOME"},
    )
    expect(
        "future AWS environment override",
        "deny",
        base,
        extra_env={"AWS_CSM_ENABLED": "true", "AWS_CSM_HOST": "127.0.0.1"},
    )
    expect(
        "unapproved inherited CA bundle",
        "deny",
        base,
        extra_env={"SSL_CERT_FILE": "/tmp/unapproved-ca.pem"},
    )
    policy_with_ca = {
        **POLICY,
        "allowed_environment": {"SSL_CERT_FILE": "/tmp/corporate-ca.pem"},
    }
    expect(
        "policy-approved inherited CA bundle",
        "allow",
        base,
        policy=policy_with_ca,
        extra_env={"SSL_CERT_FILE": "/tmp/corporate-ca.pem"},
    )

    paginated = safe("ec2", "describe-instances")
    expect("unbounded paginated read", "deny", paginated)
    expect("oversized paginated read", "deny", paginated + " --max-items 101")
    expect("zero-item paginated read", "deny", paginated + " --max-items 0")
    expect(
        "mismatched page bounds",
        "deny",
        paginated + " --max-items 25 --page-size 50",
    )
    expect(
        "duplicate max-items uses last",
        "deny",
        paginated + " --max-items 25 --page-size 25 --max-items 101",
    )
    expect(
        "abbreviated page bounds override",
        "deny",
        paginated + " --max-items 25 --page-size 25 --max-i 100000 --page-s 100000",
    )
    expect(
        "sensitive secret read",
        "deny",
        safe("secretsmanager", "get-secret-value"),
    )
    for service, operation in (
        ("amplify", "get-artifact-url"),
        ("auditmanager", "get-assessment-report-url"),
        ("auditmanager", "get-evidence-file-upload-url"),
        ("customer-profiles", "get-upload-job-path"),
        ("devicefarm", "get-upload"),
        ("devicefarm", "list-uploads"),
        ("ec2", "describe-ipam-external-resource-verification-tokens"),
        ("gamelift", "get-game-session-log-url"),
        ("groundstation", "get-agent-task-response-url"),
        ("secretsmanager", "get-random-password"),
        ("wafv2", "get-decrypted-api-key"),
        ("lambda", "get-function"),
        ("lambda", "get-function-configuration"),
        ("lambda", "get-layer-version"),
        ("lambda", "get-layer-version-by-arn"),
        ("m2", "get-signed-bluinsights-url"),
        ("mturk", "get-file-upload-url"),
        ("security-ir", "get-case-attachment-download-url"),
        ("security-ir", "get-case-attachment-upload-url"),
        ("waf", "get-change-token"),
        ("waf-regional", "get-change-token"),
    ):
        expect(
            f"sensitive material read: {service} {operation}",
            "deny",
            safe(service, operation),
        )
    expect("configure write", "deny", safe("configure", "set"))
    expect("unknown operation", "deny", safe("ec2", "future-operation"))
    expect("top-level login", "deny", safe("login", ""))
    expect("top-level logout", "deny", safe("logout", ""))
    expect("unknown top-level command", "deny", safe("totally-unknown", ""))
    expect("service without operation", "deny", safe("s3", ""))
    expect("high-level s3 ls is not globally bounded", "deny", safe("s3", "ls"))
    expect("local SSO logout mutation", "deny", safe("sso", "logout"))
    expect("logs tail has no total bound", "deny", safe("logs", "tail"))
    expect(
        "unbounded logs tail follow",
        "deny",
        safe("logs", "tail", "--follow"),
    )
    expect(
        "abbreviated unbounded logs tail follow",
        "deny",
        safe("logs", "tail", "--fol"),
    )

    for service, operation in (
        ("inspector2", "disable"),
        ("securityhub", "disable-security-hub-v2"),
        ("cloudwatch", "disable-alarm-actions"),
        ("cloudformation", "deploy"),
    ):
        expect(
            f"mutation blocked: {service} {operation}",
            "deny",
            safe(service, operation),
        )

    expect("corrupt policy", "deny", base, policy="{")
    expect("wrong-type policy", "deny", base, policy=[])
    expect("overly permissive policy", "deny", base, policy_mode=0o644)
    expect(
        "missing profiles policy",
        "deny",
        base,
        policy={"operator": {"stamp_prefix": "xx"}},
    )
    expect("malformed hook event", "deny", raw_event="{")
    expect(
        "interactive PTY denied before write_stdin bypass",
        "deny",
        raw_event=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "zsh", "tty": True}}
        ),
    )
    expect_policy_special_files_fail_fast()
    expect_inventory_special_files_fail_fast()
    expect_aws_alias_file_blocked()
    expect(
        "unparsed AWS-shaped command",
        "deny",
        "AWS_SDK_UA_APP_ID=xx-offline-test a=aw; ${a}s sts get-caller-identity",
    )
    expect(
        "unstamped variable-built aws blocked",
        "deny",
        "a=aw; ${a}s ec2 terminate-instances --instance-ids i-123",
    )
    for special in ("$@ws", "${@}ws", "$*ws", "${1}ws"):
        expect(
            f"special-parameter AWS command blocked: {special}",
            "deny",
            "set -- /safe/a; "
            + special
            + " sts get-caller-identity --profile probe-read --region us-east-1 "
            "--no-cli-pager --no-cli-auto-prompt",
        )
    expect(
        "variable trusted path blocked",
        "deny",
        "x=/safe/aws; $x sts get-caller-identity --profile probe-read "
        "--region us-east-1 --no-cli-pager",
    )
    expect(
        "command-substituted trusted path blocked",
        "deny",
        "$(printf /safe/aws) ec2 terminate-instances --instance-ids i-123",
    )
    expect(
        "backtick-substituted trusted path blocked",
        "deny",
        "`printf /safe/aws` ec2 terminate-instances --instance-ids i-123",
    )
    mutation = safe("ec2", "terminate-instances", "--instance-ids i-123")
    for name, dynamic_path in (
        ("zsh equals command lookup", "=aws"),
        ("parameter-expanded command word", "/safe/aw${:-s}"),
        ("embedded command-substituted word", "/safe/aw$(printf s)"),
        ("embedded backtick-substituted word", "/safe/aw`printf s`"),
        ("ANSI-C hex command word", r"$'/safe/\x61\x77\x73'"),
        ("ANSI-C octal command word", r"$'/safe/\141\167\163'"),
        ("ANSI-C Unicode command word", r"$'/safe/\u0061\u0077\u0073'"),
    ):
        expect(name, "deny", mutation.replace(TRUSTED, dynamic_path))
    for name, expanded_path in (
        ("question-mark globbed CLI", "/safe/aw?"),
        ("star-globbed CLI", "/safe/a*"),
        ("bracket-globbed CLI", "/safe/a[w]s"),
        ("brace-expanded CLI", "/safe/a{w,x}s"),
        ("zsh-qualified CLI", "/safe/aws(@)"),
        ("zsh question-glob-qualified CLI", "/safe/aw?(N)"),
        ("zsh bracket-glob-qualified CLI", "/safe/a[w]s(@)"),
    ):
        expect(name, "deny", mutation.replace(TRUSTED, expanded_path))
    expect(
        "copying trusted CLI for indirect execution blocked",
        "deny",
        "cp /safe/aws /tmp/x; /tmp/x ec2 terminate-instances --instance-ids i-123",
    )
    expect(
        "ANSI-C symlinked trusted CLI blocked",
        "deny",
        "ln -s $'/safe/\\x61\\x77\\x73' /tmp/x; "
        "/tmp/x sts get-caller-identity --profile probe-read --region us-east-1 "
        "--no-cli-pager --no-cli-auto-prompt",
    )
    expect(
        "cat-copied trusted CLI blocked",
        "deny",
        "/bin/cat /safe/aws > /tmp/x; chmod +x /tmp/x; "
        "/tmp/x sts get-caller-identity --profile probe-read --region us-east-1 "
        "--no-cli-pager --no-cli-auto-prompt",
    )
    expect(
        "dd-copied trusted CLI blocked",
        "deny",
        "dd if=/safe/aws of=/tmp/x; chmod +x /tmp/x; "
        "/tmp/x sts get-caller-identity --profile probe-read --region us-east-1 "
        "--no-cli-pager --no-cli-auto-prompt",
    )
    expect(
        "symlinking trusted CLI for indirect execution blocked",
        "deny",
        "ln -s /safe/aws /tmp/x; /tmp/x ec2 terminate-instances --instance-ids i-123",
    )
    expect_symlink_alias_blocked()
    expect(
        "nested mutation blocks outer safe read",
        "deny",
        base
        + ' --query "$('
        + safe("ec2", "delete-volume", "--volume-id vol-123")
        + ')"',
    )
    expect_complexity_deny_is_fast("$(" * 600 + mutation + ")" * 600)
    expect(
        "mutation in for loop blocked",
        "deny",
        "for x in one; do " + mutation + "; done",
    )
    expect(
        "mutation in while loop blocked",
        "deny",
        "while true; do " + mutation + "; done",
    )
    expect(
        "mutation in case body blocked",
        "deny",
        "case x in x) " + mutation + " ;; esac",
    )
    expect(
        "mutation in shell function blocked",
        "deny",
        "f(){ " + mutation + "; }; f",
    )
    expect(
        "mutation through dynamic shell wrapper blocked",
        "deny",
        '$SHELL -c "' + mutation + '"',
    )
    expect(
        "mutation after fused prefix redirection blocked",
        "deny",
        "2>/tmp/aws-error " + mutation,
    )
    expect(
        "mutation after spaced prefix redirection blocked",
        "deny",
        "> /tmp/aws-output " + mutation,
    )
    expect_ledger_safety()

    # Outside readonly mode, a legacy operation that would normally ask must
    # still become deny when the runtime is Codex.
    expect(
        "Codex ask maps to deny",
        "deny",
        "AWS_SDK_UA_APP_ID=xx-offline-test aws secretsmanager get-secret-value "
        "--secret-id placeholder --profile probe-read",
        mode="legacy",
    )
    print(f"Codex read-only gate: {PASSED}/{PASSED} PASS")


if __name__ == "__main__":
    main()
