#!/usr/bin/env python3
"""Preflight card for an intended aws CLI command.

A planning aid, not an enforcer: given a command you are ABOUT to run, it
classifies the operation, checks the profile against local policy, suggests a
purpose stamp, lists required tags for creates, points at the matching waiter,
and proposes a pointed read-back to verify the change afterward. It performs
no AWS calls and always exits 0 once it has a command to analyze (guidance,
not gatekeeping: the PreToolUse gate does the enforcing).

Usage:
  aws-preflight.py aws ec2 delete-volume --volume-id vol-1 --profile x
  echo 'AWS_SDK_UA_APP_ID="xx-slug" aws s3api create-bucket ...' | aws-preflight.py

Inputs (all local files):
  references/inventory/inventory.csv   operation -> class/sensitive
  references/inventory/waiters.csv     service waiters + polled operation
  ~/.claude/aws-ops.policy.json        operator prefix, profile classes,
                                       required tags (override with
                                       AWS_OPS_POLICY_FILE, same as the gate)

Missing inputs degrade conservatively: the card still prints, with an explicit
warning and the verb-taxonomy fallback (unknown verb = guarded mutation).
"""

import csv
import json
import os
import re
import shlex
import sys
from pathlib import Path

STAMP_VAR = "AWS_SDK_UA_APP_ID"

# Flags whose value is the next token (skipped when locating service/operation).
VALUE_FLAGS = {
    "--profile",
    "--region",
    "--output",
    "--endpoint-url",
    "--query",
    "--color",
    "--ca-bundle",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "--cli-binary-format",
    "--sts-regional-endpoints",
}

# Verb -> class fallback, aligned with references/operation-classes.md and the
# gate's taxonomy. First path is always the inventory; this covers misses.
VERB_CLASS = {}
for _verbs, _cls in (
    (
        "delete terminate purge destroy wipe remove revoke deregister release "
        "retire forget deprecate expire evict uninstall unsubscribe erase "
        "reboot failover switchover deprovision restart rm rb",
        "destroy",
    ),
    (
        "create register allocate provision import upload clone restore launch "
        "duplicate renew request reserve subscribe invite define purchase mb",
        "create",
    ),
    (
        "update modify put set reset replace rotate promote resize rename move "
        "apply configure assign unassign merge accept reject approve deny "
        "increase decrease attach detach associate disassociate enable disable "
        "suspend resume tag untag cancel swap transfer migrate copy grant "
        "authorize deauthorize override archive unarchive lock unlock abort "
        "add activate deactivate upgrade change dissociate write initialize "
        "pause disconnect rollback cp mv sync",
        "modify",
    ),
    (
        "invoke send publish start run execute submit trigger signal notify "
        "redrive retry replay rerun initiate complete stop test verify export "
        "generate synthesize translate transcribe detect classify recognize "
        "predict convert render evaluate poll claim confirm refresh reindex "
        "rebuild index process flush sign redeem exchange post respond resend",
        "execute",
    ),
    (
        "get list describe head lookup query scan select search check validate "
        "estimate preview simulate discover count read retrieve view resolve "
        "is filter download fetch analyze compare summarize explain peek "
        "calculate ls wait help presign",
        "read",
    ),
):
    for _v in _verbs.split():
        VERB_CLASS[_v] = _cls

# Verbs whose outcome has an unambiguous waiter state. When the verb is here,
# only a waiter carrying one of these states is a correct wait target: after a
# stop, waiting on "deleted" would hang forever, so no match beats a wrong one.
VERB_STATES = {
    "delete": ("deleted",),
    "terminate": ("terminated",),
    "remove": ("deleted", "removed"),
    "release": ("released",),
    "stop": ("stopped",),
    "start": ("running", "available", "started", "in-service"),
    "launch": ("running", "available", "in-service"),
    "create": (
        "exists",
        "available",
        "active",
        "created",
        "ready",
        "complete",
        "completed",
        "in-service",
        "running",
    ),
    "restore": ("available", "active", "completed"),
    "reboot": ("available", "running"),
}

# Waiter state words that fit each class of change, used to rank candidates.
STATE_HINT = {
    "destroy": ("deleted", "terminated", "stopped", "removed", "released"),
    "create": (
        "available",
        "exists",
        "active",
        "created",
        "in-service",
        "running",
        "complete",
        "completed",
        "ready",
    ),
    "modify": (
        "available",
        "active",
        "in-service",
        "updated",
        "modified",
        "complete",
        "completed",
    ),
    "execute": ("complete", "completed", "succeeded", "stopped", "finished"),
}

SKILL_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_CSV = SKILL_ROOT / "references" / "inventory" / "inventory.csv"
WAITERS_CSV = SKILL_ROOT / "references" / "inventory" / "waiters.csv"


def load_policy(warnings):
    path = os.environ.get(
        "AWS_OPS_POLICY_FILE", os.path.expanduser("~/.claude/aws-ops.policy.json")
    )
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        warnings.append(
            f"policy file not readable ({path}): profile classes, operator "
            "prefix and required tags are unknown: verify them by hand"
        )
        return {}


def load_inventory(warnings):
    table = {}
    try:
        with INVENTORY_CSV.open(newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) >= 4 and row[0] != "service":
                    table[(row[0], row[1])] = (row[2], row[3] == "1")
    except OSError:
        warnings.append(
            "inventory.csv not readable: falling back to the verb taxonomy "
            "(less precise; celebrated exceptions will be missed)"
        )
    return table


def load_waiters(warnings):
    waiters = {}
    try:
        with WAITERS_CSV.open(newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) >= 5 and row[0] != "service":
                    waiters.setdefault(row[0], []).append(
                        {
                            "name": row[1],
                            "delay": row[2],
                            "attempts": row[3],
                            "polls": row[4],
                        }
                    )
    except OSError:
        warnings.append("waiters.csv not readable: no waiter suggestions")
    return waiters


def classify_op(service, op, inventory):
    """Return (class, sensitive, source)."""
    hit = inventory.get((service, op))
    if hit:
        return hit[0], hit[1], "inventory"
    verb = op.split("-", 1)[0]
    if verb in ("batch", "admin") and "-" in op:
        verb = op.split("-", 2)[1]
    if verb == "assume":
        return "read", True, "verb rule (assume* mints credentials)"
    cls = VERB_CLASS.get(verb)
    if cls is None:
        return "modify", True, "unknown verb -> guarded mutation"
    return cls, cls == "destroy", f"verb rule ('{verb}')"


def tokenize(line):
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse_command(tokens):
    """Return (service, op, profile, stamp, aws_index) for the first aws call."""
    stamp = profile = None
    aws_idx = None
    for i, t in enumerate(tokens):
        if t.startswith(STAMP_VAR + "="):
            stamp = t.split("=", 1)[1].strip("'\"")
        m = re.match(r"AWS_PROFILE=(\S+)", t)
        if m:
            profile = m.group(1).strip("'\"")
        if t == "aws" or t.endswith("/aws"):
            aws_idx = i
            break
    if aws_idx is None:
        return None
    words = []
    i = aws_idx + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("&&", "||", ";", "|"):
            break
        if t.startswith("--"):
            flag = t.split("=", 1)[0]
            if flag == "--profile":
                profile = (
                    t.split("=", 1)[1]
                    if "=" in t
                    else (tokens[i + 1] if i + 1 < len(tokens) else None)
                )
            if flag in VALUE_FLAGS and "=" not in t:
                i += 2
                continue
            i += 1
            continue
        if not t.startswith("-") and len(words) < 2:
            words.append(t)
        i += 1
    service = words[0] if words else "help"
    op = words[1] if len(words) > 1 else "help"
    return service, op, profile, stamp, aws_idx


def op_nouns(op):
    """Tokens of the operation minus its verb: delete-volume -> {volume, volumes}."""
    parts = op.split("-")[1:]
    nouns = set()
    for p in parts:
        if not p:
            continue
        nouns.add(p)
        nouns.add(p.rstrip("s"))
        nouns.add(p + "s")
    return nouns


def find_waiter(service, op, cls, waiters):
    candidates = waiters.get(service, [])
    if not candidates:
        return None
    nouns = op_nouns(op)
    verb = op.split("-", 1)[0]
    required_states = VERB_STATES.get(verb)
    hint_states = STATE_HINT.get(cls, ())
    best, best_score = None, 0
    for w in candidates:
        wtoks = w["name"].split("-")
        noun_hits = sum(1 for t in wtoks if t in nouns or t.rstrip("s") in nouns)
        if noun_hits == 0:
            continue
        if required_states is not None and not any(t in required_states for t in wtoks):
            continue  # wrong terminal state for this verb: worse than no waiter
        score = noun_hits * 2
        if any(t in hint_states for t in wtoks):
            score += 3
        if score > best_score:
            best, best_score = w, score
    return best


def find_readback(service, op, inventory, waiter):
    if waiter:
        return f"aws {service} {waiter['polls']}"
    nouns = op_nouns(op)
    best, best_score = None, 0
    for (svc, cand), (cls, _sens) in inventory.items():
        if svc != service or cls != "read":
            continue
        verb = cand.split("-", 1)[0]
        if verb not in ("describe", "get", "list", "head"):
            continue
        ctoks = cand.split("-")[1:]
        hits = sum(1 for t in ctoks if t in nouns)
        if hits == 0:
            continue
        score = hits * 3 - abs(len(ctoks) - max(1, len(op.split("-")) - 1))
        score += {"describe": 2, "get": 2, "head": 1, "list": 0}[verb]
        if score > best_score:
            best, best_score = cand, score
    return f"aws {service} {best}" if best else None


def main():
    argv = sys.argv[1:]
    if argv:
        line = " ".join(shlex.quote(a) if " " in a else a for a in argv)
    else:
        line = sys.stdin.read().strip()
    if not line:
        print(
            "usage: aws-preflight.py <aws command...>   (or pipe the command on stdin)",
            file=sys.stderr,
        )
        sys.exit(2)

    warnings = []
    policy = load_policy(warnings)
    inventory = load_inventory(warnings)
    waiters = load_waiters(warnings)

    tokens = tokenize(line)
    parsed = parse_command(tokens)
    if parsed is None:
        print(
            "no 'aws' invocation found in the input; nothing to preflight",
            file=sys.stderr,
        )
        sys.exit(2)
    service, op, profile, stamp, _ = parsed

    cls, sensitive, source = classify_op(service, op, inventory)

    # Flag escalations, mirroring the gate's reasoning.
    notes = []
    if service == "s3" and op == "sync" and "--delete" in tokens:
        cls, sensitive = "destroy", True
        notes.append(
            "s3 sync --delete removes objects at the destination: destroy-tier"
        )
    if any(t == "--force" or t.startswith("--force-") for t in tokens) and cls in (
        "modify",
        "destroy",
    ):
        sensitive = True
        notes.append("--force skips built-in guards: treat as sensitive")
    if re.search(r"--acl\s+(public-read|public-read-write|authenticated-read)", line):
        sensitive = True
        notes.append("public ACL crosses an exposure boundary: sensitive")
    if "--with-decryption" in tokens and "--no-with-decryption" not in tokens:
        sensitive = True
        notes.append(
            "--with-decryption emits plaintext secret material: pipe to the consumer, keep out of transcripts"
        )
    if any(t == "--recursive" for t in tokens) and cls == "destroy":
        notes.append(
            "--recursive on a destructive verb is a mass operation: enumerate first, confirm the list, one target per command"
        )
    if "--no-verify-ssl" in tokens:
        notes.append(
            "--no-verify-ssl is never acceptable: remove it (the gate will deny)"
        )

    mutating = cls != "read"

    # Profile assessment.
    profiles = policy.get("profiles") or {}
    if profile is None:
        prof_class = None
        prof_line = "none given: the ambient default profile will be used"
        prof_warn = (
            "add an explicit --profile so the identity behind the change is deliberate"
        )
    else:
        prof_class = profiles.get(profile, "unknown")
        prof_line = f"{profile} -> {prof_class}"
        prof_warn = None
        if mutating and prof_class == "frozen":
            prof_warn = "this profile is frozen (reads only): the mutation will be denied; pick the account's mutation profile or stop"
        elif mutating and prof_class == "readonly":
            prof_warn = "read-only profile aimed at a mutation: it will fail on permissions; switch to the mutation profile only for this command"
        elif mutating and prof_class == "unknown":
            prof_warn = "profile not in local policy: confirm which account and role this is before mutating"

    # Purpose stamp.
    stamp_prefix = (
        (policy.get("operator") or {}).get("stamp_prefix") or ""
    ).strip() or "xx"
    stamped_cmd = None
    if mutating and not stamp:
        suggested = f"{stamp_prefix}-<task-slug>"
        stamped_cmd = f'{STAMP_VAR}="{suggested}" {line}'

    # Tags (creates only).
    required_tags = policy.get("required_tags") or {}
    has_tags = bool(re.search(r"--(tags|tag-specifications|tagging)\b", line))

    # Waiter and read-back.
    waiter = find_waiter(service, op, cls, waiters) if mutating else None
    readback = find_readback(service, op, inventory, waiter) if mutating else None

    # ---- card ----
    w = lambda s="": print(s)
    label = lambda k, v: print(f"  {k:<11}{v}")
    w("== aws preflight " + "=" * 45)
    label("command", line)
    label("operation", f"aws {service} {op}")
    label(
        "class",
        f"{cls}{' + sensitive' if sensitive else ''}  [{source}]",
    )
    label("profile", prof_line)
    if prof_warn:
        label("", f"!! {prof_warn}")

    if mutating:
        if stamp:
            ok = stamp.startswith(stamp_prefix + "-")
            label(
                "stamp",
                stamp
                + (
                    ""
                    if ok
                    else f"  !! does not start with the operator prefix '{stamp_prefix}-'"
                ),
            )
        else:
            label(
                "stamp",
                f"missing. suggested: {stamp_prefix}-<task-slug> (short kebab-case, fill the slug)",
            )
            label("run as", stamped_cmd)
    else:
        label("stamp", "not required (read)")

    if cls == "create":
        req = (
            ", ".join(f"{k}={v}" for k, v in required_tags.items())
            or "(none in policy)"
        )
        label("tags", f"{'present on command' if has_tags else 'MISSING on command'}")
        label("", f"required by policy: {req}")
        label(
            "", "recommended: Name, purpose=<task-slug>, owner, expires (if temporary)"
        )

    if mutating:
        if waiter:
            label(
                "waiter",
                f"aws {service} wait {waiter['name']}  "
                f"(polls {waiter['polls']}, {waiter['delay']}s x {waiter['attempts']})",
            )
        else:
            label(
                "waiter",
                "none for this operation: poll the read-back below with a bounded loop (fixed delay, max attempts), never an unbounded watch",
            )
        if readback:
            suffix = f" --profile {profile}" if profile else ""
            label(
                "read-back",
                f"{readback} <target-identifier>{suffix}   # verify the change landed",
            )
        else:
            label(
                "read-back",
                "no obvious pointed read found: use the service's describe/get for the exact resource you touched",
            )

    if cls == "destroy":
        notes.insert(
            0,
            "destructive: describe the single target first (look-before-delete) and confirm it is the intended resource",
        )
    if sensitive and cls != "destroy" and mutating:
        notes.insert(
            0,
            "sensitive: trust/exposure boundary, spend, disruption, or credential material: confirm it is authorized",
        )

    for n in notes:
        label("note", n)
    for wmsg in warnings:
        label("warn", wmsg)
    w("=" * 62)
    sys.exit(0)


if __name__ == "__main__":
    main()
