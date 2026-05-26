#!/usr/bin/env python3
"""
lint_suricata.py — minimal structural lint for Suricata signatures.

Verifies each `suricata/**/*.rules` file:
- starts with one of: alert / drop / reject / pass
- contains a `sid:NNNN;` clause
- contains a `msg:"..."` clause
- closes with a matching paren
- has a `classtype:` (warning, not error)

Exits 0 on success, 1 on the first error. Does not parse Suricata
fully — for that, run `suricata -T -c suricata.yaml` on a sensor box.
"""

from __future__ import annotations

import pathlib
import re
import sys


SID_RE = re.compile(r"\bsid:\s*\d+\s*;")
MSG_RE = re.compile(r'\bmsg:\s*"[^"]+"\s*;')
CLASSTYPE_RE = re.compile(r"\bclasstype:\s*[\w-]+\s*;")
ACTIONS = ("alert", "drop", "reject", "pass")


def lint_file(path: pathlib.Path) -> list[tuple[str, str]]:
    """Return list of (severity, message) tuples."""
    out: list[tuple[str, str]] = []
    rule = path.read_text(encoding="utf-8").strip()
    if not rule:
        return [("error", f"{path}: file is empty")]

    if not rule.startswith(ACTIONS):
        out.append(
            ("error", f"{path}: does not start with an action keyword (alert/drop/...)")
        )
    if not SID_RE.search(rule):
        out.append(("error", f"{path}: missing `sid:NNNN;` clause"))
    if not MSG_RE.search(rule):
        out.append(("error", f'{path}: missing `msg:"...";` clause'))
    if rule.count("(") != rule.count(")"):
        out.append(("error", f"{path}: unbalanced parentheses"))
    if not CLASSTYPE_RE.search(rule):
        out.append(("warning", f"{path}: no `classtype:` set (recommended)"))
    return out


def main() -> int:
    sigs_dir = pathlib.Path(__file__).resolve().parent.parent / "suricata"
    if not sigs_dir.is_dir():
        print(f"error: {sigs_dir} not found", file=sys.stderr)
        return 2

    files = sorted(sigs_dir.rglob("*.rules"))
    if not files:
        print("warning: no signature files found")
        return 0

    n_err = n_warn = 0
    for path in files:
        for severity, msg in lint_file(path):
            print(msg, file=sys.stderr)
            if severity == "error":
                n_err += 1
            else:
                n_warn += 1

    print(
        f"\n{len(files)} file(s) checked — {n_err} error(s), {n_warn} warning(s)",
        file=sys.stderr,
    )
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main())
