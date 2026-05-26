#!/usr/bin/env python3
"""
extract_rules.py — pull Sigma YAML and Suricata signatures out of the
ctf-notes/labs/*/writeup_en.md files and write them to standalone files
under rules/ and suricata/.

Usage:
    ./scripts/extract_rules.py --source PATH/TO/ctf-notes/labs

The extractor is intentionally permissive: it picks any fenced ```yaml
block whose top-level keys look like a Sigma rule (`title`, `detection`,
`logsource`) and any ```suricata block or alert/drop lines outside code
fences that match the Suricata grammar.

This script is checked in alongside the rules so the provenance of every
.yml file in this repository is auditable — re-run it against an updated
ctf-notes checkout and the rules/ tree regenerates deterministically.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Iterator

SIGMA_FENCE = re.compile(r"```yaml\n(.*?)```", re.DOTALL)
# Suricata rules in the labs writeups span multiple lines:
#   alert ... (
#     msg:"...";
#     ...
#     sid:NNNN;
#   )
# Capture the whole block from the action keyword to a closing paren
# that sits alone on its own line.
SURICATA_RULE = re.compile(
    r"^(?:alert|drop|reject|pass)\s+[\s\S]+?^\s*\)\s*$",
    re.MULTILINE,
)
SIGMA_TITLE = re.compile(r"^title:\s*(.+)$", re.MULTILINE)


def slugify(text: str) -> str:
    """Lowercase, collapse non-alnum to '_', trim."""
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s[:60] or "rule"


def is_sigma(block: str) -> bool:
    return "detection:" in block and ("logsource:" in block or "title:" in block)


def extract_sigma(text: str) -> Iterator[tuple[str, str]]:
    """Yield (slug, body) for each Sigma YAML block found."""
    seen: set[str] = set()
    for match in SIGMA_FENCE.finditer(text):
        body = match.group(1).rstrip() + "\n"
        if not is_sigma(body):
            continue
        title_match = SIGMA_TITLE.search(body)
        title = title_match.group(1).strip().strip('"') if title_match else "unnamed"
        slug = slugify(title)
        # de-dupe within the same CVE
        unique = slug
        i = 2
        while unique in seen:
            unique = f"{slug}_{i}"
            i += 1
        seen.add(unique)
        yield unique, body


def extract_suricata(text: str) -> Iterator[tuple[str, str]]:
    """Yield (slug, body) for each Suricata signature found."""
    seen: set[str] = set()
    for match in SURICATA_RULE.finditer(text):
        rule = match.group(0)
        sid_match = re.search(r"sid:\s*(\d+)", rule)
        if not sid_match:
            continue
        msg_match = re.search(r'msg:\s*"([^"]+)"', rule)
        sid = sid_match.group(1)
        msg = msg_match.group(1) if msg_match else f"sid_{sid}"
        slug = f"{sid}_{slugify(msg)}"
        if slug in seen:
            continue
        seen.add(slug)
        yield slug, rule + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--source",
        required=True,
        type=pathlib.Path,
        help="ctf-notes/labs directory to scan",
    )
    parser.add_argument(
        "--rules-out",
        default=pathlib.Path("rules"),
        type=pathlib.Path,
        help="Where Sigma rule files are written (default: ./rules)",
    )
    parser.add_argument(
        "--suricata-out",
        default=pathlib.Path("suricata"),
        type=pathlib.Path,
        help="Where Suricata signature files are written (default: ./suricata)",
    )
    args = parser.parse_args()

    if not args.source.is_dir():
        print(f"error: {args.source} is not a directory", file=sys.stderr)
        return 2

    n_sigma = n_suricata = n_cves = 0
    for cve_dir in sorted(args.source.iterdir()):
        if not cve_dir.is_dir():
            continue
        writeup = cve_dir / "writeup_en.md"
        if not writeup.is_file():
            continue

        text = writeup.read_text(encoding="utf-8")
        cve = cve_dir.name
        n_cves += 1

        rules_dir = args.rules_out / cve
        rules_dir.mkdir(parents=True, exist_ok=True)
        for slug, body in extract_sigma(text):
            (rules_dir / f"{slug}.yml").write_text(body, encoding="utf-8")
            n_sigma += 1

        sur_dir = args.suricata_out / cve
        sur_dir.mkdir(parents=True, exist_ok=True)
        for slug, rule in extract_suricata(text):
            (sur_dir / f"{slug}.rules").write_text(rule, encoding="utf-8")
            n_suricata += 1

    print(
        f"extracted {n_sigma} Sigma rule(s) and {n_suricata} Suricata "
        f"signature(s) from {n_cves} CVE directories"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
