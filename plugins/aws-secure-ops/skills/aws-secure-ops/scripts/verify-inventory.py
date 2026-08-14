#!/usr/bin/env python3
"""Integrity verifier for the classified operation inventory.

Validates references/inventory/inventory.csv against its own structural
contract and against references/inventory/summary.json, then asserts a set
of canonical classifications that the gate depends on. Read-only: it never
writes or rewrites any inventory file.

Why this exists: the inventory is the ground truth the command classifier
reads at gate time. A silently truncated CSV, a duplicated key, or a drifted
summary would degrade the gate without any visible error, so this script
fails closed -- every structural problem is a hard failure with a nonzero
exit, and missing or unreadable inputs are treated as failures too.

Usage:
    verify-inventory.py [--inventory PATH] [--summary PATH] [--quiet]

Exit codes:
    0  all checks passed (informational notes may still be printed)
    1  one or more hard failures (structure, duplicates, drift, spot-checks)
    2  inputs missing or unreadable
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

EXPECTED_HEADER = [
    "service",
    "operation",
    "class",
    "sensitive",
    "dryrun",
    "paginated",
    "source",
    "rule",
]
VALID_CLASSES = {"read", "execute", "create", "modify", "destroy"}
VALID_FLAGS = {"0", "1"}

# Canonical classifications the gate's behavior depends on. Each entry is
# (service, operation, expected_class, expected_sensitive) where
# expected_sensitive is True (must be 1) or None (not asserted).
SPOT_CHECKS = [
    ("ec2", "stop-instances", "destroy", True),
    ("ec2", "terminate-instances", "destroy", True),
    ("sts", "assume-role", "read", True),
    ("sqs", "purge-queue", "destroy", None),
    ("cloudtrail", "stop-logging", "destroy", True),
    ("iam", "create-access-key", "create", True),
    ("ssm", "send-command", "execute", True),
    ("ssm", "start-session", "execute", True),
    ("cloudformation", "execute-change-set", "modify", None),
    ("s3", "rb", "destroy", None),
    ("secretsmanager", "get-secret-value", "read", True),
]

# Summary keys reconciled against the CSV. Anything else in summary.json
# (data_dir, waiters, domain_sizes, ...) is out of scope for this check.
RECONCILED_KEYS = ("services", "operations", "class_totals", "sensitive_operations")


def default_path(name):
    return Path(__file__).resolve().parent.parent / "references" / "inventory" / name


class Report:
    def __init__(self, quiet=False):
        self.failures = []
        self.notes = []
        self.quiet = quiet

    def fail(self, msg):
        self.failures.append(msg)

    def note(self, msg):
        self.notes.append(msg)

    def section(self, title):
        if not self.quiet:
            print(f"\n== {title} ==")

    def line(self, msg):
        if not self.quiet:
            print(msg)


def load_rows(path, report):
    """Parse the CSV, enforcing header and per-row structure. Returns rows
    as a list of dicts, or None if the file is unusable."""
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                report.fail(f"inventory is empty: {path}")
                return None
            if header != EXPECTED_HEADER:
                report.fail(
                    "header mismatch: expected "
                    f"{','.join(EXPECTED_HEADER)!r} but found {','.join(header)!r}"
                )
                # A wrong header means column meanings are unknown; stop here.
                return None
            rows = []
            for lineno, fields in enumerate(reader, start=2):
                if not fields:
                    continue  # tolerate a trailing blank line only
                if len(fields) != 8:
                    report.fail(
                        f"line {lineno}: expected 8 fields, found {len(fields)}"
                    )
                    continue
                row = dict(zip(EXPECTED_HEADER, fields))
                row["_line"] = lineno
                rows.append(row)
            return rows
    except OSError as exc:
        report.fail(f"cannot read inventory: {exc}")
        return None


def check_field_values(rows, report):
    bad = 0
    for row in rows:
        if row["class"] not in VALID_CLASSES:
            report.fail(
                f"line {row['_line']}: {row['service']} {row['operation']}: "
                f"invalid class {row['class']!r}"
            )
            bad += 1
        for flag in ("sensitive", "dryrun", "paginated"):
            if row[flag] not in VALID_FLAGS:
                report.fail(
                    f"line {row['_line']}: {row['service']} {row['operation']}: "
                    f"{flag} must be 0 or 1, found {row[flag]!r}"
                )
                bad += 1
        if not row["service"] or not row["operation"]:
            report.fail(f"line {row['_line']}: empty service or operation field")
            bad += 1
    return bad


def check_duplicates(rows, report):
    seen = {}
    dups = []
    for row in rows:
        key = (row["service"], row["operation"])
        if key in seen:
            dups.append((key, seen[key], row["_line"]))
        else:
            seen[key] = row["_line"]
    for (service, operation), first, again in dups:
        report.fail(
            f"duplicate key: {service} {operation} (first at line {first}, again at line {again})"
        )
    return dups


def check_summary(rows, summary_path, report):
    try:
        with open(summary_path, encoding="utf-8") as fh:
            summary = json.load(fh)
    except (OSError, ValueError) as exc:
        report.fail(f"cannot read summary: {exc}")
        return

    for key in RECONCILED_KEYS:
        if key not in summary:
            report.fail(f"summary is missing required key {key!r}")
    if any(key not in summary for key in RECONCILED_KEYS):
        return

    actual_services = len({row["service"] for row in rows})
    actual_operations = len(rows)
    actual_classes = Counter(row["class"] for row in rows)
    actual_sensitive = sum(1 for row in rows if row["sensitive"] == "1")

    def reconcile(name, expected, actual):
        if expected == actual:
            report.line(f"  {name}: {actual} (matches summary)")
        else:
            report.fail(
                f"summary drift: {name} is {actual} in CSV but {expected} in summary"
            )

    reconcile("services", summary["services"], actual_services)
    reconcile("operations", summary["operations"], actual_operations)
    reconcile("sensitive_operations", summary["sensitive_operations"], actual_sensitive)

    summary_classes = summary["class_totals"]
    if not isinstance(summary_classes, dict):
        report.fail("summary drift: class_totals is not an object")
        return
    for cls in sorted(VALID_CLASSES | set(summary_classes)):
        reconcile(
            f"class_totals.{cls}",
            summary_classes.get(cls, 0),
            actual_classes.get(cls, 0),
        )


def check_spot_checks(rows, report):
    index = {(row["service"], row["operation"]): row for row in rows}
    for service, operation, expected_class, expected_sensitive in SPOT_CHECKS:
        label = f"{service} {operation}"
        row = index.get((service, operation))
        if row is None:
            report.fail(f"spot-check: {label} is missing from the inventory")
            continue
        problems = []
        if row["class"] != expected_class:
            problems.append(f"class is {row['class']!r}, expected {expected_class!r}")
        if expected_sensitive and row["sensitive"] != "1":
            problems.append("sensitive is 0, expected 1")
        if problems:
            report.fail(f"spot-check: {label}: " + "; ".join(problems))
        else:
            want = expected_class + ("+sensitive" if expected_sensitive else "")
            report.line(f"  ok: {label} = {want}")


def coverage_note(rows, report):
    unknown_rule = sum(1 for row in rows if row["rule"] == "unknown")
    review_source = sum(1 for row in rows if row["source"] == "review")
    report.note(f"rows with rule=unknown: {unknown_rule}")
    report.note(f"rows with source=review: {review_source}")


def main():
    parser = argparse.ArgumentParser(
        description="Verify the classified operation inventory."
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=default_path("inventory.csv"),
        help="path to inventory.csv (default: skill references/inventory/)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=default_path("summary.json"),
        help="path to summary.json (default: skill references/inventory/)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print only failures and the final verdict"
    )
    args = parser.parse_args()

    report = Report(quiet=args.quiet)

    for path, label in ((args.inventory, "inventory"), (args.summary, "summary")):
        if not path.is_file():
            print(f"FAIL: {label} file not found: {path}", file=sys.stderr)
            return 2

    report.section("Structure")
    rows = load_rows(args.inventory, report)
    if rows is None:
        for msg in report.failures:
            print(f"  FAIL: {msg}", file=sys.stderr)
        print("\nRESULT: FAIL (inventory unreadable or malformed)", file=sys.stderr)
        return 2
    bad_values = check_field_values(rows, report)
    report.line(f"  rows parsed: {len(rows)}")
    report.line(f"  field-value problems: {bad_values}")

    report.section("Duplicate keys")
    dups = check_duplicates(rows, report)
    report.line(f"  duplicate (service, operation) keys: {len(dups)}")

    report.section("Summary reconciliation")
    check_summary(rows, args.summary, report)

    report.section("Canonical spot-checks")
    check_spot_checks(rows, report)

    report.section("Coverage notes (informational)")
    coverage_note(rows, report)
    for msg in report.notes:
        report.line(f"  {msg}")

    print()
    if report.failures:
        print(f"RESULT: FAIL ({len(report.failures)} problem(s))")
        for msg in report.failures:
            print(f"  FAIL: {msg}")
        return 1
    print(
        "RESULT: PASS -- inventory is structurally sound and consistent with its summary"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
