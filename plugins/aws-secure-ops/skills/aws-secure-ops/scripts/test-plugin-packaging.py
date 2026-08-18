#!/usr/bin/env python3
"""Repository-contained packaging contract for both plugin runtimes."""

import json
import re
from pathlib import Path


SCRIPT = Path(__file__).resolve()
PLUGIN = SCRIPT.parents[3]
REPO = SCRIPT.parents[5]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def load(path):
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    assert isinstance(value, dict), f"{path} must contain an object"
    return value


def main():
    codex = load(PLUGIN / ".codex-plugin" / "plugin.json")
    claude = load(PLUGIN / ".claude-plugin" / "plugin.json")
    hooks = load(PLUGIN / "hooks" / "hooks.json")
    marketplace = load(REPO / ".agents" / "plugins" / "marketplace.json")
    claude_marketplace = load(REPO / ".claude-plugin" / "marketplace.json")

    version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    assert SEMVER.fullmatch(version), version
    assert codex["name"] == claude["name"] == "aws-secure-ops"
    assert codex["version"] == claude["version"] == version
    assert (PLUGIN / "README.md").is_file()
    assert (PLUGIN / "LICENSE").is_file()
    assert (PLUGIN / codex["skills"]).resolve() == (PLUGIN / "skills").resolve()

    assert marketplace["name"] == "secure-ops"
    entries = [p for p in marketplace["plugins"] if p.get("name") == "aws-secure-ops"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["source"] == {
        "source": "local",
        "path": "./plugins/aws-secure-ops",
    }
    assert (REPO / entry["source"]["path"]).resolve() == PLUGIN
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }

    claude_entries = [
        p
        for p in claude_marketplace["plugins"]
        if p.get("name") == "aws-secure-ops"
    ]
    assert len(claude_entries) == 1
    assert claude_entries[0]["version"] == version
    assert (REPO / claude_entries[0]["source"]).resolve() == PLUGIN

    skill = (PLUGIN / "skills" / "aws-secure-ops" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert skill.startswith("---\n")
    frontmatter = skill.split("---\n", 2)[1]
    assert re.search(r"(?m)^name:\s*aws-secure-ops\s*$", frontmatter)
    assert re.search(r"(?m)^description:\s*>-\s*$", frontmatter)

    groups = hooks["hooks"]
    pretool = groups["PreToolUse"][0]
    assert re.fullmatch(pretool["matcher"], "Bash")
    precommand = pretool["hooks"][0]["command"]
    for marker in (
        "run-gate.sh",
        "--codex-pretool",
        "classify-aws-command.py",
        "AWS_OPS_HOOK_RUNTIME=codex",
        "AWS_OPS_MODE=readonly",
        'permissionDecision":"deny',
    ):
        assert marker in precommand, marker
    session_command = groups["SessionStart"][0]["hooks"][0]["command"]
    for marker in (
        "run-gate.sh",
        "--codex-session",
        "aws-ops-doctor.py",
        "--quick --session",
        "systemMessage",
    ):
        assert marker in session_command, marker

    print("Plugin packaging contract: PASS")


if __name__ == "__main__":
    main()
