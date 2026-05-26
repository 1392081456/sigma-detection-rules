# sigma-detection-rules

> A curated **detection-as-code** ruleset for published N-day CVEs — Sigma rules, Suricata signatures, and an extractor that regenerates the tree from upstream lab writeups.

[![ci](https://github.com/1392081456/sigma-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/1392081456/sigma-detection-rules/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Sigma rules](https://img.shields.io/badge/Sigma_rules-30-blue)
![Suricata signatures](https://img.shields.io/badge/Suricata_signatures-24-blue)
![Hunting queries](https://img.shields.io/badge/Hunting_queries-6_CVEs_×_3_SIEMs-blue)
![CVE coverage](https://img.shields.io/badge/CVE_coverage-23-blue)

## What this is

Every rule in this repository corresponds to a **published CVE that has been reproduced in an isolated vulhub Docker container**. The rules are not aspirational — they were authored while watching the actual exploit traffic against a known-vulnerable, locally-hosted target, then validated against the patched version of the same software to check for false positives.

The repository ships:

| Path | What's in it |
|---|---|
| [`rules/`](rules/) | 30 Sigma YAML rules, grouped by CVE directory |
| [`suricata/`](suricata/) | 24 Suricata signatures (`.rules` files), grouped by CVE directory |
| [`hunting/`](hunting/) | **Threat-hunting queries** for 6 representative CVEs in 3 SIEM dialects (Splunk SPL / Sentinel KQL / Elastic ES\|QL), each with a post-hunt pivot |
| [`scripts/extract_rules.py`](scripts/extract_rules.py) | Pulls rules out of the upstream [`ctf-notes/labs/*/writeup_en.md`](https://github.com/1392081456/ctf-notes/tree/main/labs) writeups so the tree is regenerable |
| [`scripts/lint_sigma.py`](scripts/lint_sigma.py) | Structural lint for Sigma YAML — required fields, parseable, has a `detection.condition` |
| [`scripts/lint_suricata.py`](scripts/lint_suricata.py) | Structural lint for Suricata — `sid` / `msg` / balanced parens / classtype |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Runs both linters on every push and PR; emits a stats table to the job summary |

## Why a separate repo (vs. just landing rules in ctf-notes)

`ctf-notes` is a research notebook — each writeup explains *why* a detection rule looks the way it does. This repository is the **distributable artifact** of that research:

- **CI gate.** Every rule that lands here has passed structural lint; broken or half-written drafts stay in the upstream writeup chapter.
- **SID range discipline.** Suricata SIDs in `9_000_000`–`9_999_999` are reserved for this project, so deployments can drop the entire `suricata/` tree into `local.rules` without colliding with vendor rulesets.
- **Auditable provenance.** Every `.yml` and `.rules` file is the deterministic output of `scripts/extract_rules.py` against a specific `ctf-notes` commit — no hidden hand-edits.

## Quick start

### Use the rules

```sh
git clone https://github.com/1392081456/sigma-detection-rules.git
# Sigma → convert to your backend with sigma-cli
sigma convert -t splunk rules/log4j_2021_44228/*.yml
# Suricata → concatenate into local.rules
cat suricata/**/*.rules >> /etc/suricata/rules/local.rules
suricata -T -c /etc/suricata/suricata.yaml
```

### Regenerate the tree (for contributors)

```sh
git clone https://github.com/1392081456/ctf-notes.git ../ctf-notes
./scripts/extract_rules.py --source ../ctf-notes/labs
python scripts/lint_sigma.py
python scripts/lint_suricata.py
```

## CVE coverage

23 CVE directories at the time of v0.1.0. Each row links to the upstream `ctf-notes/labs` writeup that explains the *why* behind the rule.

| Year | CVE | Software | Class |
|---|---|---|---|
| 2016 | [CVE-2016-4437](https://github.com/1392081456/ctf-notes/tree/main/labs/shiro_550) | Apache Shiro 1.x | Java cookie deserialization |
| 2017 | [Fastjson 1.2.24](https://github.com/1392081456/ctf-notes/tree/main/labs/fastjson_1224_rce) | Fastjson | AutoType deserialization |
| 2019 | [CVE-2019-12725](https://github.com/1392081456/ctf-notes/tree/main/labs/zeroshell_2019_12725) | ZeroShell | URL parameter command injection |
| 2021 | [CVE-2021-44228](https://github.com/1392081456/ctf-notes/tree/main/labs/log4j_2021_44228) | Log4j 2.x | JNDI lookup → remote class loading |
| 2022 | [CVE-2022-22965](https://github.com/1392081456/ctf-notes/tree/main/labs/spring_2022_22965) | Spring Framework | ClassLoader binding (Spring4Shell) |
| 2023 | [CVE-2023-38646](https://github.com/1392081456/ctf-notes/tree/main/labs/metabase_2023_38646) | Metabase | JDBC URL `INIT` injection |
| 2023 | [CVE-2023-46604](https://github.com/1392081456/ctf-notes/tree/main/labs/activemq_2023_46604) | ActiveMQ OpenWire | Non-HTTP deserialization |
| 2023 | [CVE-2023-4450](https://github.com/1392081456/ctf-notes/tree/main/labs/jimureport_2023_4450) | JimuReport | FreeMarker SSTI |
| 2024 | [CVE-2024-23897](https://github.com/1392081456/ctf-notes/tree/main/labs/jenkins_2024_23897) | Jenkins CLI | `@filename` arbitrary read |
| 2024 | [CVE-2024-27198](https://github.com/1392081456/ctf-notes/tree/main/labs/teamcity_2024_27198) | TeamCity | Path-parameter auth bypass |
| 2024 | [CVE-2024-36401](https://github.com/1392081456/ctf-notes/tree/main/labs/geoserver_2024_36401) | GeoServer | XPath/EL injection |
| 2024 | [CVE-2024-4956](https://github.com/1392081456/ctf-notes/tree/main/labs/nexus_2024_4956) | Nexus Repository | Jetty path traversal |
| 2024 | [CVE-2024-9264](https://github.com/1392081456/ctf-notes/tree/main/labs/grafana_2024_9264) | Grafana | DuckDB SQLi → shellfs |
| 2025 | [CVE-2025-29927](https://github.com/1392081456/ctf-notes/tree/main/labs/nextjs_2025_29927) | Next.js | Middleware authorization bypass |
| 2025 | [CVE-2025-3248](https://github.com/1392081456/ctf-notes/tree/main/labs/langflow_2025_3248) | Langflow | Pre-auth Python decorator exec |
| 2025 | [CVE-2025-49001](https://github.com/1392081456/ctf-notes/tree/main/labs/dataease_2025_49001) | DataEase | JWT signature bypass |
| 2026 | [CVE-2026-22777](https://github.com/1392081456/ctf-notes/tree/main/labs/comfyui_2026_22777) | ComfyUI-Manager | CRLF → config downgrade → RCE |
| 2026 | [CVE-2026-24061](https://github.com/1392081456/ctf-notes/tree/main/labs/inetutils_2026_24061) | GNU InetUtils telnetd | USER argument injection |
| 2026 | [CVE-2026-25253](https://github.com/1392081456/ctf-notes/tree/main/labs/openclaw_2026_25253) | OpenClaw | Cross-Site WebSocket Hijacking |
| 2026 | [CVE-2026-25887](https://github.com/1392081456/ctf-notes/tree/main/labs/chartbrew_2026_25887) | Chartbrew | MongoDB `new Function()` RCE |
| 2026 | [CVE-2026-34197](https://github.com/1392081456/ctf-notes/tree/main/labs/activemq_2026_34197) | Apache ActiveMQ | Jolokia → Spring XML RCE |
| 2026 | [CVE-2026-34486](https://github.com/1392081456/ctf-notes/tree/main/labs/tomcat_2026_34486) | Tomcat Tribes | EncryptInterceptor bypass |
| — | [Redis 4.x unauth](https://github.com/1392081456/ctf-notes/tree/main/labs/redis_4_unacc) | Redis | Unauth → crontab / SSH / webshell |

## Scope statement

Every rule in this repository was authored against a **locally-hosted, vendor-patched-image vulhub Docker container** or an equivalent isolated lab VM. **No production system, third-party service, or unauthorized network was touched at any stage of authoring or testing.** The intent of this repository is consistently defensive — every rule's existence is justified by a published CVE with a vendor patch available years before the rule was written.

## Methodology

See the companion blog post: [From CVE Advisory to Sigma Rule in 30 Minutes](https://1392081456.github.io/2026/05/26/cve-to-sigma-30min/) — describes the four-step workflow (Reproduce → Sigma → Suricata → SIEM hunt) that produced every rule here.

## Author

Maintained by Colorful White ([@1392081456](https://github.com/1392081456)) — independent defensive-security researcher at Guangdong University of Technology. Academic record at [DOI: 10.3778/j.issn.1002-8331.2311-0227](https://doi.org/10.3778/j.issn.1002-8331.2311-0227). CTFtime: [@colorfulwhitez](https://ctftime.org/user/261101) (team APWN).

## License

[MIT](LICENSE).
