#!/usr/bin/env python3
"""Apply reviewed classification corrections to the operation inventory.

Input: a JSON file containing either a list of correction objects or any
nested structure containing them (objects with service/operation/class/
sensitive keys are collected recursively). Each correction:

  {"service": "ec2", "operation": "stop-instances",
   "class": "destroy", "sensitive": 1, "reason": "disrupts live workload"}

Rows are matched by (service, operation); on a hit the class and sensitive
columns are updated and the source column is set to "review". Misses are
reported, not silently dropped. The inventory CSV is rewritten in place with
a .bak alongside.
"""

import csv
import json
import sys
from pathlib import Path

VALID = {"read", "execute", "create", "modify", "destroy"}


def collect(node, out):
    if isinstance(node, dict):
        if {"service", "operation", "class"} <= set(node.keys()):
            out.append(node)
        else:
            for v in node.values():
                collect(v, out)
    elif isinstance(node, list):
        for v in node:
            collect(v, out)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: apply-corrections.py <corrections.json> <inventory.csv>")
    corr_path, inv_path = Path(sys.argv[1]), Path(sys.argv[2])

    corrections = []
    collect(json.loads(corr_path.read_text()), corrections)
    if not corrections:
        sys.exit("no corrections found in input")

    fixes = {}
    for c in corrections:
        cls = str(c["class"]).strip().lower()
        if cls not in VALID:
            print(f"skip invalid class: {c}", file=sys.stderr)
            continue
        sens = 1 if int(c.get("sensitive", 0)) else 0
        fixes[(c["service"].strip(), c["operation"].strip())] = (cls, sens)

    rows = []
    header = None
    with inv_path.open(newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows = list(reader)

    applied = 0
    changed = 0
    hit = set()
    for r in rows:
        key = (r[0], r[1])
        if key in fixes:
            hit.add(key)
            applied += 1
            new_cls, new_sens = fixes[key]
            if r[2] != new_cls or r[3] != str(new_sens):
                r[2], r[3] = new_cls, str(new_sens)
                if len(r) >= 7:
                    r[6] = "review"
                if len(r) >= 8:
                    r[7] = "reviewed"
                changed += 1

    misses = sorted(set(fixes) - hit)
    bak = inv_path.with_suffix(".csv.bak")
    bak.write_bytes(inv_path.read_bytes())
    with inv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)

    print(
        json.dumps(
            {
                "corrections_in": len(fixes),
                "rows_matched": applied,
                "rows_changed": changed,
                "unmatched": [f"{s},{o}" for s, o in misses],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
