#!/usr/bin/env python3
"""
lint_sigma.py — minimal structural lint for Sigma rule YAML files.

Verifies each `rules/**/*.yml` file:
- parses as YAML
- has the required top-level keys: title, logsource, detection
- has a `detection.condition` clause
- has at least one selection/filter under `detection`

Exits 0 on success, 1 on the first failure. Designed to be called from
the CI workflow at `.github/workflows/ci.yml`.

Does NOT validate Sigma semantics (use sigma-cli for that). The point of
this lint is to catch the most common mistakes — typos in field names,
missing detection blocks — without taking a heavy dependency.
"""

from __future__ import annotations

import pathlib
import sys

try:
    import yaml  # type: ignore
except ImportError:
    print("error: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)


REQUIRED_TOP_KEYS = {"title", "logsource", "detection"}


def _check_one(rule: object, path: pathlib.Path, idx: int | None) -> list[str]:
    """Validate a single YAML document; idx is None for single-doc files."""
    where = f"{path}" if idx is None else f"{path} (doc {idx})"
    errors: list[str] = []

    if not isinstance(rule, dict):
        return [f"{where}: top-level YAML is not a mapping"]

    missing = REQUIRED_TOP_KEYS - rule.keys()
    if missing:
        errors.append(f"{where}: missing required keys: {sorted(missing)}")

    detection = rule.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append(f"{where}: detection has no `condition` clause")
        selections = [k for k in detection if k != "condition"]
        if not selections:
            errors.append(f"{where}: detection has no selection/filter keys")
    elif detection is not None:
        errors.append(f"{where}: detection is not a mapping")
    return errors


def lint_file(path: pathlib.Path) -> list[str]:
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        return [f"{path}: invalid YAML ({exc})"]

    # filter out empty documents (trailing --- etc.)
    docs = [d for d in docs if d is not None]
    if not docs:
        return [f"{path}: empty file"]

    if len(docs) == 1:
        return _check_one(docs[0], path, None)

    errors: list[str] = []
    for i, doc in enumerate(docs, start=1):
        errors.extend(_check_one(doc, path, i))
    return errors


def main() -> int:
    rules_dir = pathlib.Path(__file__).resolve().parent.parent / "rules"
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} not found", file=sys.stderr)
        return 2

    files = sorted(rules_dir.rglob("*.yml"))
    if not files:
        print("warning: no rule files found")
        return 0

    all_errors: list[str] = []
    for path in files:
        all_errors.extend(lint_file(path))

    if all_errors:
        for err in all_errors:
            print(err, file=sys.stderr)
        print(
            f"\n{len(all_errors)} lint error(s) across {len(files)} file(s)",
            file=sys.stderr,
        )
        return 1

    print(f"OK — {len(files)} Sigma rule(s) passed structural lint")
    return 0


if __name__ == "__main__":
    sys.exit(main())
