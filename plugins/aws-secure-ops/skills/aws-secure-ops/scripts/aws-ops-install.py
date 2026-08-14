#!/usr/bin/env python3
"""Wire the aws-secure-ops PreToolUse gate into settings.json without the plugin.

Claude Code plugins register the gate for you through the marketplace. This
installer does the same job by hand, for people who run the skill without the
plugin system: it merges a single PreToolUse Bash hook into
``~/.claude/settings.json`` that runs this skill's ``classify-aws-command.py``
before every Bash command, backing up the file first and preserving every hook
already there.

Design constraints (all deliberate):

  * **Dependency-free and portable.** Standard library only; no assumption of
    macOS. The interpreter that runs this script is the one written into the
    hook, so the wiring matches the machine it was installed on.
  * **Idempotent.** The hook is keyed by the absolute path of this skill's
    ``classify-aws-command.py``. A second run finds it and changes nothing; it
    never stacks a duplicate.
  * **Fail closed.** A settings file that will not parse is left untouched and
    the run exits nonzero. Nothing is guessed, nothing is silently overwritten.
  * **Reversible.** ``--uninstall`` removes only the entry whose command
    references this gate, leaving every other hook exactly as it was. The
    policy file and shim line survive unless ``--purge`` is also passed.

Overrides for testing (never touch the real home in a test):
  * ``HOME`` selects the ``~/.claude`` directory (honored via the standard
    library, POSIX and Windows alike).
  * ``AWS_OPS_SETTINGS_FILE`` or ``--settings PATH`` overrides the settings
    file location outright.
  * ``AWS_OPS_POLICY_FILE`` overrides where the policy file is scaffolded (the
    same variable the gate reads at runtime).
  * ``AWS_OPS_ZSHRC`` overrides the shell rc file the ``--with-shim`` line is
    appended to.

Usage:
    python3 aws-ops-install.py [install]      # default action
    python3 aws-ops-install.py --with-shim    # also source aws-shim.sh in zsh
    python3 aws-ops-install.py --uninstall    # remove only our hook entry
    python3 aws-ops-install.py --uninstall --purge   # also drop policy + shim
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
GATE = SCRIPTS / "classify-aws-command.py"
SHIM = SCRIPTS / "aws-shim.sh"
DOCTOR = SCRIPTS / "aws-ops-doctor.py"

STATUS_MESSAGE = "aws-secure-ops gate"
HOOK_TIMEOUT = 15
BASH_MATCHER = "Bash"

# An agnostic starting point: neutral placeholders only, the contract shape
# documented in SKILL.md. The operator replaces these with real profile names
# and account IDs in their private copy; this file never ships filled in.
POLICY_TEMPLATE = {
    "operator": {"name": "the operator", "stamp_prefix": "xx"},
    "profiles": {
        "prod-read": "readonly",
        "prod-admin": "admin",
        "legacy-frozen": "frozen",
        "personal-lab": "personal",
    },
    "frozen_accounts": ["111111111111"],
    "required_tags": {
        "environment": "production",
        "team": "example-team",
        "owner": "the operator",
    },
    "notes": "Replace placeholders with your real profiles and account IDs.",
}


# ---------------------------------------------------------------------------
# Path resolution (all overridable for a sandboxed test)
# ---------------------------------------------------------------------------


def claude_dir() -> Path:
    """The ~/.claude directory, resolved through HOME so a test can redirect it."""
    return Path.home() / ".claude"


def settings_path(cli_override: str = "") -> Path:
    if cli_override:
        return Path(cli_override).expanduser()
    env = os.environ.get("AWS_OPS_SETTINGS_FILE")
    if env:
        return Path(env).expanduser()
    return claude_dir() / "settings.json"


def policy_path() -> Path:
    env = os.environ.get("AWS_OPS_POLICY_FILE")
    if env:
        return Path(env).expanduser()
    return claude_dir() / "aws-ops.policy.json"


def zshrc_path() -> Path:
    env = os.environ.get("AWS_OPS_ZSHRC")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".zshrc"


# ---------------------------------------------------------------------------
# Hook shape and matching
# ---------------------------------------------------------------------------


def hook_command() -> str:
    """The command string the hook runs: this interpreter, then the gate.

    Both paths are double-quoted so a space anywhere in the install prefix
    survives the shell that the harness uses to run the hook.
    """
    return '"{interp}" "{gate}"'.format(interp=sys.executable, gate=GATE)


def our_hook() -> dict:
    return {
        "type": "command",
        "command": hook_command(),
        "timeout": HOOK_TIMEOUT,
        "statusMessage": STATUS_MESSAGE,
    }


def references_gate(hook: object) -> bool:
    """True when a hook entry runs our specific classify-aws-command.py.

    Keyed on the gate's absolute path, so an unrelated hook that merely mentions
    a different classify script (or any other command) is never touched.
    """
    return (
        isinstance(hook, dict)
        and hook.get("type") == "command"
        and str(GATE) in str(hook.get("command", ""))
    )


# ---------------------------------------------------------------------------
# Settings I/O (fail closed on unreadable or malformed input)
# ---------------------------------------------------------------------------


def load_settings(path: Path) -> dict:
    """Return the parsed settings, or {} when the file is absent or empty.

    A file that exists but does not parse as a JSON object is a hard error: we
    refuse to overwrite it, because guessing would risk clobbering real config.
    """
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            "FAIL  {p} is not valid JSON ({e}); refusing to modify it. "
            "Fix or move the file and re-run.".format(p=path, e=exc)
        )
    if not isinstance(data, dict):
        raise SystemExit(
            "FAIL  {p} top level is not a JSON object; refusing to modify it.".format(
                p=path
            )
        )
    return data


def backup_settings(path: Path) -> Path:
    """Timestamped copy beside the original. Only called when the file exists."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    backup = path.with_name(path.name + ".bak." + stamp)
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backup


def write_settings(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Policy scaffold and shim line (each independently idempotent)
# ---------------------------------------------------------------------------


def scaffold_policy() -> None:
    path = policy_path()
    if path.exists():
        print("ok    policy present, left untouched: {p}".format(p=path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(POLICY_TEMPLATE, indent=2) + "\n", encoding="utf-8")
    print("ok    scaffolded placeholder policy: {p}".format(p=path))
    print("      edit it with your real profiles and account IDs before trusting it.")


def add_shim_line() -> None:
    rc = zshrc_path()
    source_line = 'source "{shim}"'.format(shim=SHIM)
    existing = rc.read_text(encoding="utf-8") if rc.exists() else ""
    if str(SHIM) in existing:
        print("ok    shim already sourced in {p}".format(p=rc))
        return
    rc.parent.mkdir(parents=True, exist_ok=True)
    prefix = "" if existing == "" or existing.endswith("\n") else "\n"
    with rc.open("a", encoding="utf-8") as fh:
        fh.write(
            prefix
            + "\n# aws-secure-ops: route terminal aws commands through the gate\n"
            + source_line
            + "\n"
        )
    print("ok    added shim source line to {p}".format(p=rc))
    if not SHIM.exists():
        print(
            "warn  {s} is not present yet; the source line is inert until it exists.".format(
                s=SHIM
            )
        )


def remove_shim_line() -> None:
    rc = zshrc_path()
    if not rc.exists():
        return
    lines = rc.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = []
    for line in lines:
        if str(SHIM) in line or line.strip() == (
            "# aws-secure-ops: route terminal aws commands through the gate"
        ):
            continue
        kept.append(line)
    rc.write_text("".join(kept), encoding="utf-8")
    print("ok    removed shim source line from {p}".format(p=rc))


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------


def run_doctor() -> None:
    if not DOCTOR.is_file():
        print("warn  aws-ops-doctor.py not found; skipping health check.")
        return
    print("\n--- aws-ops-doctor ---")
    try:
        proc = subprocess.run(
            [sys.executable, str(DOCTOR)],
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            print(
                "warn  doctor exited {c}; review the checks above.".format(
                    c=proc.returncode
                )
            )
    except Exception as exc:  # never let the doctor sink a good install
        print(
            "warn  could not run doctor: {t}: {e}".format(t=type(exc).__name__, e=exc)
        )


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def action_install(args) -> int:
    if not GATE.is_file():
        raise SystemExit(
            "FAIL  gate not found at {g}; is the skill checkout intact?".format(g=GATE)
        )

    path = settings_path(args.settings)
    settings = load_settings(path)

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SystemExit("FAIL  settings 'hooks' is present but is not an object.")
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise SystemExit(
            "FAIL  settings 'hooks.PreToolUse' is present but is not a list."
        )

    already = any(
        isinstance(entry, dict)
        and any(references_gate(h) for h in entry.get("hooks", []) or [])
        for entry in pre
    )

    if already:
        print("ok    gate hook already installed in {p} (no change).".format(p=path))
    else:
        if path.exists():
            backup = backup_settings(path)
            print("ok    backed up existing settings to {b}".format(b=backup))
        else:
            print("ok    no existing settings.json; creating a fresh one.")
        pre.append({"matcher": BASH_MATCHER, "hooks": [our_hook()]})
        write_settings(path, settings)
        print("ok    merged PreToolUse Bash gate hook into {p}".format(p=path))

    scaffold_policy()

    if args.with_shim:
        add_shim_line()

    if not args.no_doctor:
        run_doctor()

    print("\nInstall complete. The gate now guards every Bash command in this client.")
    return 0


def action_uninstall(args) -> int:
    path = settings_path(args.settings)

    if not path.exists():
        print("ok    no settings file at {p}; nothing to uninstall.".format(p=path))
    else:
        settings = load_settings(path)
        hooks = settings.get("hooks")
        removed = 0
        if isinstance(hooks, dict) and isinstance(hooks.get("PreToolUse"), list):
            backup = backup_settings(path)
            print("ok    backed up existing settings to {b}".format(b=backup))
            new_pre = []
            for entry in hooks["PreToolUse"]:
                if not isinstance(entry, dict):
                    new_pre.append(entry)
                    continue
                entry_hooks = entry.get("hooks", []) or []
                kept = [h for h in entry_hooks if not references_gate(h)]
                removed += len(entry_hooks) - len(kept)
                if not kept and "hooks" in entry:
                    # The entry existed only to carry our hook: drop it whole.
                    continue
                entry["hooks"] = kept
                new_pre.append(entry)
            hooks["PreToolUse"] = new_pre
            write_settings(path, settings)
        if removed:
            print(
                "ok    removed {n} gate hook entr{y} from {p}; other hooks left intact.".format(
                    n=removed, y="y" if removed == 1 else "ies", p=path
                )
            )
        else:
            print("ok    no gate hook found in {p}; nothing to remove.".format(p=path))

    if args.purge:
        pol = policy_path()
        if pol.exists():
            pol.unlink()
            print("ok    purged policy file {p}".format(p=pol))
        remove_shim_line()
    else:
        print("ok    policy file and shim line left in place (pass --purge to remove).")

    print("\nUninstall complete.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Wire (or remove) the aws-secure-ops gate in settings.json "
        "for non-plugin users.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="install",
        choices=["install"],
        help="the default and only positional action; use --uninstall to revert.",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="remove only this gate's hook entry; keep every other hook.",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="with --uninstall, also delete the policy file and the shim line.",
    )
    parser.add_argument(
        "--with-shim",
        action="store_true",
        help="also append a 'source aws-shim.sh' line to the shell rc file.",
    )
    parser.add_argument(
        "--settings",
        default="",
        help="override the settings.json path (for testing / non-standard homes).",
    )
    parser.add_argument(
        "--no-doctor",
        action="store_true",
        help="skip the post-install health check (used by the test harness).",
    )
    args = parser.parse_args()

    if args.purge and not args.uninstall:
        parser.error("--purge only applies together with --uninstall.")

    if args.uninstall:
        return action_uninstall(args)
    return action_install(args)


if __name__ == "__main__":
    sys.exit(main())
