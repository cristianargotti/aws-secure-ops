#!/usr/bin/env python3
"""Data-driven decision corpus runner for the aws-secure-ops gate.

Reads a JSONL corpus of gate decisions and replays every case through the real
classifier (classify-aws-command.py) via the same PreToolUse hook envelope the
agent harness uses. Fully offline: no AWS calls, a throwaway policy per case, and
the decision ledger is routed to os.devnull so a corpus run never touches the
operator's real ledger.

Each corpus line is one JSON object:
  {
    "id":            "unique-slug",                 # required
    "command":       "AWS_SDK_UA_APP_ID=xx-t aws …",# required (the Bash string)
    "expect":        "allow" | "ask" | "deny",      # required
    "reason_substr": "purpose stamp",               # optional, case-insensitive
    "policy":        { … } | null,                  # optional; default below
    "expected_fail": true,                          # optional; a known gap not
                                                    #   yet fixed (reported XFAIL)
    "finding":       "F1",                           # optional label
    "note":          "…"                             # optional
  }

Exit status: 0 when every non-expected_fail case matches; 1 otherwise. An
`expected_fail` case that matches anyway is reported as XPASS (informational,
never a failure) so newly-closed gaps are visible.

Usage:
  run-corpus.py [--corpus PATH] [--gate PATH] [--quiet] [--only SUBSTR]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CORPUS = HERE / "corpus" / "decisions.jsonl"
DEFAULT_GATE = HERE / "classify-aws-command.py"

# Default throwaway policy when a case does not supply its own.
DEFAULT_POLICY = {
    "operator": {"name": "corpus", "stamp_prefix": "xx"},
    "profiles": {
        "adm": "admin",
        "ro": "readonly",
        "frz": "frozen",
        "pers": "personal",
    },
    "required_tags": {},
    "ledger": False,
}


def decide(gate, command, policy):
    """Run one command through the gate; return (decision, reason)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(policy, fh)
        policy_path = fh.name
    try:
        env = dict(os.environ)
        env["AWS_OPS_POLICY_FILE"] = policy_path
        env["AWS_OPS_LEDGER_FILE"] = os.devnull
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
        proc = subprocess.run(
            [sys.executable, str(gate)],
            input=event,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        out = proc.stdout.strip()
        if not out:
            return "allow", ""
        obj = json.loads(out)["hookSpecificOutput"]
        return obj.get("permissionDecision", "?"), obj.get(
            "permissionDecisionReason", ""
        )
    finally:
        os.unlink(policy_path)


def load_corpus(path):
    cases = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cases.append(json.loads(line))
            except ValueError as exc:
                raise SystemExit(f"corpus line {lineno}: invalid JSON ({exc})")
    return cases


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--gate", type=Path, default=DEFAULT_GATE)
    ap.add_argument(
        "--quiet", action="store_true", help="print only failures + summary"
    )
    ap.add_argument(
        "--only", default="", help="run only cases whose id contains SUBSTR"
    )
    args = ap.parse_args()

    for p, label in ((args.corpus, "corpus"), (args.gate, "gate")):
        if not p.is_file():
            print(f"FATAL: {label} not found: {p}", file=sys.stderr)
            return 2

    cases = load_corpus(args.corpus)
    if args.only:
        cases = [c for c in cases if args.only in c.get("id", "")]

    npass = nfail = nxfail = nxpass = 0
    for c in cases:
        cid = c.get("id", "<no-id>")
        command = c.get("command")
        expect = c.get("expect")
        if command is None or expect not in ("allow", "ask", "deny"):
            print(f"FAIL  {cid}: malformed case (need command + expect)")
            nfail += 1
            continue
        policy = c.get("policy") or DEFAULT_POLICY
        got, reason = decide(args.gate, command, policy)
        substr = c.get("reason_substr") or ""
        ok = got == expect and (not substr or substr.lower() in reason.lower())

        if c.get("expected_fail"):
            if ok:
                nxpass += 1
                print(f"XPASS {cid}: now closed (was expected_fail) — promote it")
            else:
                nxfail += 1
                if not args.quiet:
                    print(f"xfail {cid}: still open (got {got!r})")
            continue

        if ok:
            npass += 1
            if not args.quiet:
                print(f"PASS  {cid}")
        else:
            nfail += 1
            detail = f"want {expect!r}" + (f"+/{substr}/" if substr else "")
            print(f"FAIL  {cid}: got {got!r} ({detail}) :: {reason[:120]}")

    print()
    print(
        f"passed={npass} failed={nfail} xfail={nxfail} xpass={nxpass} "
        f"total={len(cases)}"
    )
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
