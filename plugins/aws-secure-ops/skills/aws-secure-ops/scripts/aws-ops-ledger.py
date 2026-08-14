#!/usr/bin/env python3
"""Operator CLI over the local AWS operations decision ledger.

The hardened gate appends one JSON object per line for every aws invocation it
inspects (allow, ask, and deny alike). This tool reads that JSONL file and
answers the operator's questions: what happened, when, under which stamp, and
how to reconcile those stamps against the org audit trail (CloudTrail).

This tool never runs an aws command and never touches the network. Every
subcommand except `rotate` is read-only. `rotate` performs the single
maintenance action the tool is allowed: it renames the active ledger aside to
a timestamped sibling so a fresh file starts empty. It only ever renames --
never rewrites, edits, or deletes ledger content -- so the metadata-only
contract and the recorded bytes are preserved intact.

Ledger path resolution: $AWS_OPS_LEDGER_FILE if set, else
~/.claude/aws-ops-ledger.jsonl.

Line schema (metadata only, by contract -- no command text, no secrets):
  {"ts": ISO-8601 UTC, "service": str, "operation": str, "class": str,
   "sensitive": bool, "decision": "allow"|"ask"|"deny", "stamp": str|null,
   "profile": str|null, "profile_class": str|null}

Subcommands:
  tail [N]    last N entries (default 20), one human-readable line each
  summary     counts by decision, by class, sensitive count, stamps, time span
  stamps      distinct purpose stamps with counts (for CloudTrail reconciliation)
  reconcile   print (do not run) bounded CloudTrail lookup commands per stamp
  rotate      rename the active ledger aside to a timestamped sibling
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_LEDGER = Path.home() / ".claude" / "aws-ops-ledger.jsonl"
EXPECTED_KEYS = {
    "ts",
    "service",
    "operation",
    "class",
    "sensitive",
    "decision",
    "stamp",
    "profile",
    "profile_class",
}


def ledger_path() -> Path:
    env = os.environ.get("AWS_OPS_LEDGER_FILE")
    return Path(env).expanduser() if env else DEFAULT_LEDGER


def load_entries(path: Path):
    """Return (entries, malformed_count). Unknown fields are ignored, never
    printed; only the contract's metadata fields are read."""
    entries = []
    malformed = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, TypeError):
                    malformed += 1
                    continue
                if not isinstance(obj, dict):
                    malformed += 1
                    continue
                entries.append({k: obj.get(k) for k in EXPECTED_KEYS})
    except OSError as exc:
        print(f"error: cannot read ledger at {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    return entries, malformed


def parse_ts(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    # Coerce a naive timestamp (a hand-crafted or foreign ledger line with no
    # UTC offset) to aware UTC, so it never raises when compared against the
    # gate's offset-aware timestamps during sort/summary.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fmt_ts(value) -> str:
    dt = parse_ts(value)
    if dt is None:
        return str(value) if value else "????-??-??T??:??:??"
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def fmt_entry(e: dict) -> str:
    decision = str(e.get("decision") or "?")
    klass = str(e.get("class") or "?")
    svc = str(e.get("service") or "?")
    op = str(e.get("operation") or "?")
    stamp = e.get("stamp") or "-"
    profile = e.get("profile") or "-"
    pclass = e.get("profile_class")
    prof = f"{profile}({pclass})" if pclass else str(profile)
    flag = " SENSITIVE" if e.get("sensitive") else ""
    return (
        f"{fmt_ts(e.get('ts'))}  {decision:<5} {klass:<8} "
        f"{svc} {op}  stamp={stamp}  profile={prof}{flag}"
    )


def warn_malformed(malformed: int, path: Path):
    if malformed:
        print(
            f"warning: skipped {malformed} malformed line(s) in {path}",
            file=sys.stderr,
        )


def empty_exit(path: Path):
    print(f"Ledger is empty or not present yet: {path}")
    print(
        "Nothing to report. The gate writes one line per inspected aws "
        "invocation; run some operations first, or check "
        "AWS_OPS_LEDGER_FILE if you expected entries here."
    )
    sys.exit(0)


def cmd_tail(entries, argv):
    n = 20
    if argv:
        try:
            n = int(argv[0])
        except ValueError:
            print(f"error: tail expects a number, got {argv[0]!r}", file=sys.stderr)
            sys.exit(2)
        if n <= 0:
            print("error: tail expects a positive number", file=sys.stderr)
            sys.exit(2)
    for e in entries[-n:]:
        print(fmt_entry(e))


def cmd_summary(entries):
    decisions = Counter(str(e.get("decision") or "?") for e in entries)
    classes = Counter(str(e.get("class") or "?") for e in entries)
    sensitive = sum(1 for e in entries if e.get("sensitive"))
    stamps = {e["stamp"] for e in entries if e.get("stamp")}
    times = sorted(t for t in (parse_ts(e.get("ts")) for e in entries) if t)

    print(f"Entries:        {len(entries)}")
    if times:
        span = times[-1] - times[0]
        print(
            f"Time span:      {fmt_ts(times[0].isoformat())} -> "
            f"{fmt_ts(times[-1].isoformat())}  ({span})"
        )
    print(f"Sensitive:      {sensitive}")
    print(f"Distinct stamps: {len(stamps)}")
    print("By decision:")
    for k in sorted(decisions, key=lambda k: -decisions[k]):
        print(f"  {k:<8} {decisions[k]}")
    print("By class:")
    for k in sorted(classes, key=lambda k: -classes[k]):
        print(f"  {k:<8} {classes[k]}")


def stamp_stats(entries):
    """{stamp: {count, first, last}} for entries that carry a stamp."""
    stats = {}
    for e in entries:
        stamp = e.get("stamp")
        if not stamp:
            continue
        t = parse_ts(e.get("ts"))
        s = stats.setdefault(stamp, {"count": 0, "first": None, "last": None})
        s["count"] += 1
        if t is not None:
            if s["first"] is None or t < s["first"]:
                s["first"] = t
            if s["last"] is None or t > s["last"]:
                s["last"] = t
    return stats


def cmd_stamps(entries):
    stats = stamp_stats(entries)
    unstamped = sum(1 for e in entries if not e.get("stamp"))
    if not stats:
        print("No purpose stamps recorded yet.")
        if unstamped:
            print(f"({unstamped} entries carry no stamp.)")
        return
    print(f"{'stamp':<32} {'count':>5}  first seen           last seen")
    for stamp in sorted(
        stats,
        key=lambda s: stats[s]["last"] or datetime.min.replace(tzinfo=timezone.utc),
    ):
        s = stats[stamp]
        first = fmt_ts(s["first"].isoformat()) if s["first"] else "?"
        last = fmt_ts(s["last"].isoformat()) if s["last"] else "?"
        print(f"{stamp:<32} {s['count']:>5}  {first}  {last}")
    if unstamped:
        print(
            f"\n{unstamped} entries carry no stamp (typically identity "
            "checks or denied calls)."
        )


def cmd_reconcile(entries):
    stats = stamp_stats(entries)
    if not stats:
        print("No purpose stamps in the ledger, nothing to reconcile.")
        return

    # Most recent stamps first; keep the command list short and pointed.
    recent = sorted(
        stats.items(),
        key=lambda kv: kv[1]["last"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:5]

    print("CloudTrail reconciliation -- commands to run (printed, NOT run).")
    print()
    print("Each stamp below was set via AWS_SDK_UA_APP_ID, so it appears in")
    print("CloudTrail as a userAgent containing 'app/<stamp>'. CloudTrail's")
    print("lookup attributes cannot match on userAgent directly, so the")
    print("commands below pull a small, time-bounded page of events and")
    print("filter on the raw event JSON client-side with --query.")
    print()
    print("Expect a visibility lag: CloudTrail typically delivers events to")
    print("Event history within about 5-15 minutes of the API call. A stamp")
    print("missing right after the fact usually means 'not delivered yet',")
    print("not 'not recorded' -- re-run the lookup after the lag before")
    print("drawing conclusions.")
    print()
    print("Use a read-only profile, and stamp the lookup itself.")
    print()

    for stamp, s in recent:
        first = s["first"] or datetime.now(timezone.utc)
        last = s["last"] or datetime.now(timezone.utc)
        # Small buffer around the ledger window for clock skew and delivery.
        start = (first - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = (last + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(
            f"# stamp {stamp} -- {s['count']} ledger entries, "
            f"{fmt_ts(first.isoformat())} -> {fmt_ts(last.isoformat())}"
        )
        print(
            f'AWS_SDK_UA_APP_ID="{stamp}" aws cloudtrail lookup-events \\\n'
            f"  --profile <read-only-profile> \\\n"
            f"  --start-time {start} --end-time {end} \\\n"
            f"  --max-items 25 \\\n"
            f"  --query \"Events[?contains(CloudTrailEvent, 'app/{stamp}')]."
            f'{{time:EventTime,event:EventName,source:EventSource}}" \\\n'
            f"  --output table"
        )
        print()
    print("If a bounded page comes back empty after the lag, widen the time")
    print("window slightly or raise --max-items in small steps -- keep every")
    print("lookup pointed and bounded rather than paging the whole trail.")


def rotate_target(path: Path, stamp: str) -> Path:
    """Timestamped sibling in the same directory: <stem>-<stamp><suffix>.

    On the rare same-second collision, append a short counter so an existing
    rotated file is never overwritten."""
    candidate = path.with_name(f"{path.stem}-{stamp}{path.suffix}")
    if not candidate.exists():
        return candidate
    n = 1
    while True:
        candidate = path.with_name(f"{path.stem}-{stamp}-{n}{path.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def cmd_rotate(argv):
    """Rename the active ledger aside so the next write starts a fresh file.

    Best-effort and safe: it only ever renames, never deletes or rewrites, so
    ledger content cannot be lost or corrupted. A missing or empty ledger is a
    no-op that exits 0. With --if-larger-than <bytes> it rotates only when the
    file strictly exceeds that size (how the session watchdog calls it);
    otherwise it is a no-op that exits 0. Any failure exits nonzero with a
    clear stderr message, leaving the original file untouched."""
    threshold = None
    if argv:
        if argv[0] != "--if-larger-than":
            print(f"error: rotate: unknown argument {argv[0]!r}", file=sys.stderr)
            sys.exit(2)
        if len(argv) < 2:
            print(
                "error: rotate: --if-larger-than requires a byte count",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            threshold = int(argv[1])
        except ValueError:
            print(
                f"error: rotate: --if-larger-than expects an integer, got {argv[1]!r}",
                file=sys.stderr,
            )
            sys.exit(2)
        if threshold < 0:
            print(
                "error: rotate: --if-larger-than expects a non-negative integer",
                file=sys.stderr,
            )
            sys.exit(2)
        if len(argv) > 2:
            print(
                f"error: rotate: unexpected extra argument {argv[2]!r}",
                file=sys.stderr,
            )
            sys.exit(2)

    path = ledger_path()

    try:
        size = path.stat().st_size
    except FileNotFoundError:
        print(f"Ledger not present, nothing to rotate: {path}")
        sys.exit(0)
    except OSError as exc:
        print(f"error: rotate: cannot stat ledger at {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if size == 0:
        print(f"Ledger is empty, nothing to rotate: {path}")
        sys.exit(0)

    if threshold is not None and size <= threshold:
        print(
            f"Ledger is {size} bytes, at or under the {threshold}-byte "
            f"threshold; no rotation."
        )
        sys.exit(0)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = rotate_target(path, stamp)

    try:
        # os.rename within one directory is atomic on POSIX: the ledger is
        # never in a half-moved state, so a concurrent gate write cannot lose
        # data. The next gate write recreates the active file from scratch.
        os.rename(path, target)
    except OSError as exc:
        print(
            f"error: rotate: could not rename ledger {path} -> {target}: "
            f"{exc}; original left untouched",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Rotated ledger: {path} -> {target} ({size} bytes)")
    sys.exit(0)


USAGE = """usage: aws-ops-ledger.py <subcommand>

subcommands:
  tail [N]    show the last N ledger entries (default 20)
  summary     counts by decision and class, sensitive count, stamps, time span
  stamps      distinct purpose stamps with counts and first/last seen
  reconcile   print ready-to-paste CloudTrail lookup commands per recent stamp
  rotate      rename the active ledger aside to a timestamped sibling
              (optional: --if-larger-than <bytes> rotates only past that size)
"""


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE, end="")
        sys.exit(0 if argv and argv[0] in ("-h", "--help", "help") else 2)

    cmd, rest = argv[0], argv[1:]
    if cmd not in ("tail", "summary", "stamps", "reconcile", "rotate"):
        print(f"error: unknown subcommand {cmd!r}\n", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        sys.exit(2)

    # rotate is the one maintenance action; it manages the file itself and must
    # not go through the read-only empty/load path below.
    if cmd == "rotate":
        cmd_rotate(rest)
        return

    path = ledger_path()
    if not path.exists() or path.stat().st_size == 0:
        empty_exit(path)

    entries, malformed = load_entries(path)
    if not entries:
        warn_malformed(malformed, path)
        empty_exit(path)

    # Ledger lines are appended in order, but sort defensively by timestamp.
    entries.sort(
        key=lambda e: parse_ts(e.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)
    )

    if cmd == "tail":
        cmd_tail(entries, rest)
    elif cmd == "summary":
        cmd_summary(entries)
    elif cmd == "stamps":
        cmd_stamps(entries)
    elif cmd == "reconcile":
        cmd_reconcile(entries)

    warn_malformed(malformed, path)


if __name__ == "__main__":
    main(sys.argv[1:])
