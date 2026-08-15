#!/usr/bin/env python3
"""Release consistency check: one version, declared everywhere.

The version is hand-duplicated across several files; a forgotten edit ships a
marketplace advertising a different version than the plugin it installs. This
asserts the version is identical across the root VERSION file, the skill VERSION
file, plugin.json, and marketplace.json, and that CHANGELOG.md documents it. Run
it in CI so a release never ships mismatched version metadata.

Usage:
  release.py --check     # exit 0 if consistent, 1 if not
  release.py             # same as --check
"""

import json
import re
import sys
from pathlib import Path


def find_root(start: Path) -> Path:
    for p in [start, *start.parents]:
        if (p / ".claude-plugin" / "marketplace.json").is_file():
            return p
    sys.exit("release: could not locate repo root (no .claude-plugin/marketplace.json)")


def main() -> int:
    root = find_root(Path(__file__).resolve().parent)
    skill = root / "plugins" / "aws-secure-ops" / "skills" / "aws-secure-ops"

    canonical = (root / "VERSION").read_text(encoding="utf-8").strip()
    sources = {"VERSION (root, canonical)": canonical}
    try:
        sources["skill VERSION"] = (
            (skill / "VERSION").read_text(encoding="utf-8").strip()
        )
        sources["plugin.json"] = json.loads(
            (
                root / "plugins" / "aws-secure-ops" / ".claude-plugin" / "plugin.json"
            ).read_text(encoding="utf-8")
        )["version"]
        mkt = json.loads(
            (root / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )
        sources["marketplace.json (plugin)"] = mkt["plugins"][0]["version"]
        top = mkt.get("version")
        if top is not None:
            sources["marketplace.json (top)"] = top
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"release: could not read a version source: {type(exc).__name__}: {exc}")
        return 1

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    has_heading = bool(
        re.search(r"(?m)^##\s*\[" + re.escape(canonical) + r"\]", changelog)
    )

    problems = [
        f"{name} = {v!r}, expected {canonical!r}"
        for name, v in sources.items()
        if v != canonical
    ]
    if not has_heading:
        problems.append(f"CHANGELOG.md has no '## [{canonical}]' heading")

    if problems:
        print(f"release: version INCONSISTENT (canonical = {canonical}):")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1
    print(f"release: OK -- every source declares {canonical}; CHANGELOG documents it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
