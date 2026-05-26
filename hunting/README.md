# Hunting Queries

> **Threat-hunting queries** for the same CVEs covered by [`../rules/`](../rules/) (Sigma) and [`../suricata/`](../suricata/) (Suricata).
> The rules in those directories are **alerts** (real-time, condition-based). The queries here are **hunts** — written for retrospective analysis when you suspect an exploit has already happened and you need to surface evidence from existing logs.

## Format

Each CVE has one markdown file containing the same hunt expressed in three dialects:

- **Splunk SPL** — for Splunk Enterprise / Cloud
- **Microsoft Sentinel KQL** — for Microsoft Sentinel (Azure Monitor)
- **Elastic ES|QL** — for Elastic Security (≥ 8.11)

The three dialects are intentionally parallel — same fields filtered, same time window logic, same output columns — so a SOC analyst on any of the three stacks can use the hunt without translation.

## Coverage

| CVE | Software | File |
|---|---|---|
| CVE-2016-4437 | Apache Shiro 1.x | [`shiro_550.md`](shiro_550.md) |
| CVE-2021-44228 | Apache Log4j 2.x | [`log4j_2021_44228.md`](log4j_2021_44228.md) |
| CVE-2022-22965 | Spring Framework | [`spring_2022_22965.md`](spring_2022_22965.md) |
| CVE-2024-23897 | Jenkins CLI | [`jenkins_2024_23897.md`](jenkins_2024_23897.md) |
| CVE-2024-27198 | TeamCity | [`teamcity_2024_27198.md`](teamcity_2024_27198.md) |
| CVE-2024-36401 | GeoServer | [`geoserver_2024_36401.md`](geoserver_2024_36401.md) |

More CVE hunts will be added as the underlying writeup chapter ([`ctf-notes/labs`](https://github.com/1392081456/ctf-notes/tree/main/labs)) grows. Contributions follow the same template (see [`../CONTRIBUTING.md`](../CONTRIBUTING.md)).

## Why hunting queries are separate from alerts

The same vulnerability looks different through these two lenses:

- An **alert** fires on a *single bad event*: e.g., one HTTP request whose User-Agent contains `${jndi:`. It must be high-precision because every alert costs an analyst's time.
- A **hunt** scans across *all events in a window* (often weeks of data) and produces a frequency table, a top-N list, or a graph. It can be much higher-recall — the analyst is *expecting* to look through results.

Most SOC teams run alerts on **30 % of CVEs** (the loud ones) and hunts on **none**. The hunts here exist to flip that ratio.
