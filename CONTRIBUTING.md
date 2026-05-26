# Contributing

Thanks for taking an interest. This ruleset is curated — every entry must trace back to a reproducible vulhub lab in [`ctf-notes/labs`](https://github.com/1392081456/ctf-notes/tree/main/labs).

## Adding a new CVE

1. **Reproduce** the CVE in a local vulhub container (`127.0.0.1` only) and write a writeup in `ctf-notes/labs/<vendor>_<year>_<id>/writeup_en.md` following the four-step template (Overview / Attack chain / Reproduction / Lessons / Defense).
2. In the **Defense** section, embed:
   - A fenced ```` ```yaml ```` block containing a complete Sigma rule with `title / id / status / description / references / logsource / detection / condition / falsepositives / level`.
   - A fenced block (any language tag, including blank) containing one or more Suricata signatures. Each signature must include `msg`, `sid` (use the reserved 9-million range to avoid collisions), `classtype`, and `reference:cve,YYYY-XXXXX`.
3. Re-run the extractor against the updated ctf-notes checkout:

   ```sh
   ./scripts/extract_rules.py --source PATH/TO/ctf-notes/labs
   ```

4. Run the lint scripts:

   ```sh
   python scripts/lint_sigma.py
   python scripts/lint_suricata.py
   ```

5. Open a PR. CI will repeat the lint.

## Lint expectations

- Every Sigma rule must parse as YAML and contain `title`, `logsource`, `detection.condition`, and at least one selection clause. Use `level: low|medium|high|critical`.
- Every Suricata signature must include `sid:`, `msg:"..."`, balanced parens, and (recommended) `classtype:`. SIDs allocated for this repository live in the `9_000_000`–`9_999_999` range.
- All rules must reference the upstream advisory (NVD CVE entry, vendor PSIRT, or original disclosure post) so a defender can verify the claim.

## Scope statement

This repository is published for **defensive use** — building production-grade detection content from CVEs that already have vendor patches available. All authoring is done against local Docker labs (vulhub) and public CTF challenges; no production system or unauthorized network is touched at any stage. See the [scope statement in ctf-notes](https://github.com/1392081456/ctf-notes#authorization-and-targets) for the full constraint set.
