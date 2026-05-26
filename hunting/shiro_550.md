# Hunt — Apache Shiro RememberMe Deserialization (CVE-2016-4437)

> Look for **long base64-encoded `rememberMe` cookies** in web access logs. Pivot from any hit to that source IP's full session and exit traffic.

## Detection key

Shiro 1.x with the default AES key accepts a `rememberMe` cookie that it base64-decodes, AES-CBC-decrypts with hardcoded key `kPH+bIxk5D2deZiIxcaaaA==`, and feeds to Java `ObjectInputStream`. A legitimate Shiro user's `rememberMe` cookie is short (≈ 50 chars). An exploit cookie carrying a gadget chain (`CommonsBeanutils1` / `TemplatesImpl` / `JRMP`) is **typically 800 – 4000 chars**.

## Splunk SPL

```spl
index=webserver earliest=-90d cookie="*rememberMe=*"
| rex field=cookie "rememberMe=(?<rm>[A-Za-z0-9+/=]+)"
| eval rm_len = len(rm)
| where rm_len > 64
| stats count, max(rm_len) as max_len, dc(uri_path) as paths by src_ip
| sort -count
```

## Microsoft Sentinel KQL

```kusto
let lookback = 90d;
W3CIISLog
| where TimeGenerated > ago(lookback)
| where csCookie has "rememberMe="
| extend rm = extract(@"rememberMe=([A-Za-z0-9+/=]+)", 1, csCookie)
| where strlen(rm) > 64
| summarize hits = count(),
            max_cookie_len = max(strlen(rm)),
            paths = dcount(csUriStem)
    by cIP
| order by hits desc
```

## Elastic ES|QL

```esql
FROM logs-apache.access-*
| WHERE @timestamp > NOW() - 90 days
| WHERE http.request.cookie LIKE "%rememberMe=%"
| EVAL rm = REPLACE(http.request.cookie, "^.*rememberMe=([A-Za-z0-9+/=]+).*$", "$1")
| EVAL rm_len = LENGTH(rm)
| WHERE rm_len > 64
| STATS hits = COUNT(*), max_len = MAX(rm_len), paths = COUNT_DISTINCT(url.path) BY source.ip
| SORT hits DESC
```

## Post-hunt pivot — did the exploit succeed?

A successful RememberMe deserialization spawns a child process via Java's `Runtime.exec`. Check process-creation logs on the application server for the time window of any hit above:

```spl
index=hosts earliest=-90d
| where parent_process_name="java" 
| where process_name IN ("sh", "bash", "cmd.exe", "powershell.exe", "curl", "wget", "nc", "ncat")
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count by host, process_cmdline
| sort -count
```

The combination of "long rememberMe cookie hit at time T" + "java spawned shell at time T+1 to T+30" is high-confidence successful exploitation.
