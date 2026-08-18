#!/usr/bin/env python3
"""Offline contract tests for the shared Claude/Codex hook dispatcher."""

import json
import os
import subprocess
import tempfile
from pathlib import Path


PLUGIN = Path(__file__).resolve().parents[3]
HOOKS = PLUGIN / "hooks" / "hooks.json"


def make_root(base, name, manifests):
    root = base / name
    for manifest in manifests:
        path = root / manifest / "plugin.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    scripts = root / "skills" / "aws-secure-ops" / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "run-gate.sh").write_text(
        'printf "%s:%s\\n" "${AWS_OPS_HOOK_RUNTIME:-claude}" "$*"\n',
        encoding="utf-8",
    )
    (scripts / "classify-aws-command.py").write_text("\n", encoding="utf-8")
    (scripts / "aws-ops-doctor.py").write_text("\n", encoding="utf-8")
    return root


def invoke(command, plugin_root, claude_root, extra_env=None):
    env = os.environ.copy()
    env["PLUGIN_ROOT"] = str(plugin_root)
    env["CLAUDE_PLUGIN_ROOT"] = str(claude_root)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["/bin/sh", "-c", command],
        input="{}",
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def main():
    payload = json.loads(HOOKS.read_text(encoding="utf-8"))
    commands = {
        event: payload["hooks"][event][0]["hooks"][0]["command"]
        for event in ("PreToolUse", "SessionStart")
    }
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        codex = make_root(base, "codex", (".codex-plugin", ".claude-plugin"))
        claude = make_root(base, "claude", (".claude-plugin",))
        missing = base / "missing"

        for event, command in commands.items():
            result = invoke(command, codex, codex)
            assert result.returncode == 0, (event, result.stderr)
            assert result.stdout.startswith("codex:"), (event, result.stdout)

            result = invoke(command, missing, claude)
            assert result.returncode == 0, (event, result.stderr)
            assert result.stdout.startswith("claude:"), (event, result.stdout)

            result = invoke(command, codex, claude)
            assert result.returncode == 0, (event, result.stderr)
            assert result.stdout.startswith("codex:"), (event, result.stdout)

            result = invoke(
                command,
                codex,
                codex,
                {
                    "BASH_FUNC_printf%%": "() { :; }",
                    "BASH_FUNC_test%%": "() { return 1; }",
                },
            )
            assert result.returncode == 0, (event, result.stderr)
            assert result.stdout.startswith("codex:"), (event, result.stdout)

            result = invoke(command, missing, missing)
            assert result.returncode == 0, (event, result.returncode)
            payload = json.loads(result.stdout)
            if event == "PreToolUse":
                assert payload["hookSpecificOutput"]["permissionDecision"] == "deny", (
                    payload
                )
            else:
                assert "systemMessage" in payload, payload

            broken = make_root(
                base,
                "broken-" + event.lower(),
                (".codex-plugin", ".claude-plugin"),
            )
            target = (
                "classify-aws-command.py"
                if event == "PreToolUse"
                else "aws-ops-doctor.py"
            )
            (broken / "skills" / "aws-secure-ops" / "scripts" / target).unlink()
            result = invoke(command, broken, broken)
            assert result.returncode == 0, (event, result.stderr)
            assert not result.stdout.startswith("claude:"), (event, result.stdout)
            payload = json.loads(result.stdout)
            if event == "PreToolUse":
                assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
            else:
                assert "systemMessage" in payload

            print(f"PASS {event} runtime dispatch")

    print("Hook dispatch: 2/2 PASS")


if __name__ == "__main__":
    main()
