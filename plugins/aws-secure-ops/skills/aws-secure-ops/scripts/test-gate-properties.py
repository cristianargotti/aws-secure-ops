#!/usr/bin/env python3
"""Property / differential test for the gate.

A gate decision must be INVARIANT under transforms that do not change what the
shell would actually execute. Every bypass the audit found was exactly this: a
syntactic variation (=/space/quote, a wrapper, a newline) that flipped the
decision. This reuses the decision corpus as seeds and applies decision-preserving
transforms, asserting the decision is unchanged. Deterministic (no randomness), so
it is safe to run in CI.

Transforms:
  double-space       collapse/expand inter-token whitespace
  trailing-comment   append a `# ...` comment
  bash-c-wrap        wrap the whole command in `bash -c '...'` (the gate unwraps it)
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "classify-aws-command.py"
CORPUS = HERE / "corpus" / "decisions.jsonl"
DEFAULT_POLICY = {
    "operator": {"stamp_prefix": "xx"},
    "profiles": {"adm": "admin", "ro": "readonly", "frz": "frozen", "pers": "personal"},
    "required_tags": {},
    "ledger": False,
}


def decide(cmd, policy):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(policy, fh)
    fh.close()
    try:
        env = dict(os.environ)
        env["AWS_OPS_POLICY_FILE"] = fh.name
        env["AWS_OPS_LEDGER_FILE"] = os.devnull
        p = subprocess.run(
            [sys.executable, str(GATE)],
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        out = p.stdout.strip()
        if not out:
            return "allow"
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    finally:
        os.unlink(fh.name)


def transforms(cmd):
    out = {"double-space": "  ".join(cmd.split(" "))}
    if "#" not in cmd:
        out["trailing-comment"] = cmd + "  # audit note"
    # Wrapping in single quotes only preserves the decision when the command has
    # no single quote, newline, or comment of its own, AND no shell operator: an
    # operator moved inside the quotes is over-split by the (quote-unaware) segment
    # splitter, which deliberately errs strict, so the wrap is not decision-neutral.
    if not any(tok in cmd for tok in ("'", "\n", "#", "&", "|", ";")):
        out["bash-c-wrap"] = "bash -c '" + cmd + "'"
    return out


def main():
    cases = [
        json.loads(ln)
        for ln in CORPUS.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    npass = nfail = 0
    for c in cases:
        policy = c.get("policy") or DEFAULT_POLICY
        cmd = c["command"]
        base = decide(cmd, policy)
        for tname, tcmd in transforms(cmd).items():
            got = decide(tcmd, policy)
            if got == base:
                npass += 1
            else:
                nfail += 1
                print(
                    f"FAIL  {c.get('id', '?')} [{tname}]: base={base!r} transformed={got!r}"
                )
    print(f"\nproperties: passed={npass} failed={nfail} (seeds={len(cases)})")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
