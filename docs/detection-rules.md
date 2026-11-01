# Detection Rules Reference (Справочник правил детектирования)

В этом документе собраны все кастомные и настроенные правила, которые используются в лаборатории для обнаружения атак, с указанием их уровней критичности и маппинга на MITRE ATT&CK.

## 🛡️ Suricata (L3/L4)

Правила лежат в файле `hosts/victim/suricata/custom.rules`. Они отвечают за детект сетевых аномалий.

| SID | Что детектит | MITRE ATT&CK |
|:---|:---|:---|
| `1000001` | SYN Flood (stateful, count 200/5s) | T1498.001 |
| `1000002` | UDP Flood (stateful, count 500/5s) | T1498.002 |
| `1000009` | ICMP Flood (stateful, count 50/5s) | T1498.001 |
| `1000010` | ACK Flood (stateful, count 200/5s) | T1498.001 |
| `1000011` | RST Flood (stateful, count 200/5s) | T1498.001 |
| `1000003` | XMAS Scan (`flags:FPU`) | T1046 |
| `1000004` | NULL Scan (`flags:0,12`) | T1046 |
| `1000005` | FIN Scan (`flags:F`) | T1046 |
| `1000012` | LAND Attack (source IP = dest IP) | T1498.001 |
| `1000013` | Invalid TCP flags SYN+FIN | T1498.001 |
| `1000014` | Invalid TCP flags SYN+RST | T1498.001 |
| `2009582` | Nmap SYN Scan (включено из ET Open) | T1046 |

**Дополнительно:** В файле `pass.rules` настроено исключение (whitelist) для IP Wazuh Server (`192.168.56.10`), чтобы служебный трафик агента не вызывал ложных срабатываний.

## 🧠 Wazuh (SIEM & Active Response)

Правила лежат в `hosts/wazuh-server/wazuh/manager/local_rules.xml`. Они коррелируют события от Suricata, WAF и Nginx.

### Группа 1: Coraza WAF (L7)
| ID | Уровень | Что детектит | MITRE | Active Response |
|:---|:---:|:---|:---|:---:|
| `100100` | 0 | Базовое (все JSON от Coraza) | — | — |
| `100101` | 10 | WAF заблокировал запрос (`is_interrupted`) | T1190 | — |
| `100104` | 12 | SQL Injection (regex по `audit.log`) | T1190 | — |

### Группа 2: Nginx (L7)
| ID | Уровень | Что детектит | MITRE | Active Response |
|:---|:---:|:---|:---|:---:|
| `100102` | 3 | POST-запрос на страницу логина DVWA | — | — |
| `100103` | 10 | Brute Force (5+ попыток за 60с) | T1110 | ✅ 600s |
| `100300` | 10 | HTTP Flood (код 429 из `access.log`) | T1498.001 | ✅ 600s |
| `100301` | 7 | Таймауты и обрывы Nginx (408/499) | T1498.001 | — |
| `100302` | 10 | Slowloris (таймаут из `error.log`) | T1498.001 | ✅ 600s |

### Группа 3: Suricata (L3/L4)
| ID | Уровень | Что детектит | MITRE | Active Response |
|:---|:---:|:---|:---|:---:|
| `100200` | 10 | SYN Flood (на базе SID 1000001) | T1498.001 | ✅ 600s |
| `100201` | 10 | UDP Flood (на базе SID 1000002) | T1498.002 | ✅ 600s |
| `100202` | 10 | XMAS/NULL/FIN сканы | T1046 | ✅ 600s |
| `100203` | 10 | Nmap Scan (ET SCAN) | T1046 | ✅ 300s |
| `100204` | 10 | ICMP Flood (SID 1000009) | T1498.001 | ✅ 600s |
| `100205` | 10 | ACK Flood (SID 1000010) | T1498.001 | ✅ 600s |
| `100206` | 10 | RST Flood (SID 1000011) | T1498.001 | ✅ 600s |
| `100207` | 10 | LAND / Invalid Flags (SID 1000012-14) | T1498.001 | ✅ 600s |

### Группа 4: SSH (Fail2Ban)
| ID | Уровень | Что детектит | MITRE | Active Response |
|:---|:---:|:---|:---|:---:|
| `100400` | 10 | SSH Brute Force (5+ ошибок `5760` за 120с) | T1110 | — (работает Fail2Ban) |

## 🚦 OWASP Coraza WAF (L7)

Кастомные правила лежат в `hosts/victim/waf-coraza/override.conf`. Они дополняют базовый OWASP CRS (Paranoia Level 1).

| ID | Что детектит | Действие |
|:---|:---|:---|
| `10001` | Обфускация SQLi (`UNION/**/SELECT`) | Блокировка (403) |
| `10002` | Double URL Encoding (`%2527`) | Блокировка (403) |
| `10003` | Множественные SQL-комментарии | Блокировка (403) |
| `10004` | User-Agent от сканера SQLMap | Блокировка (403) |

**Встроенные правила CRS, которые чаще всего срабатывали:**
* `942100` — SQL Injection (libinjection).
* `942120` — SQL Injection (UNION).
* `941100` — XSS.
* `932100` — Remote Command Execution (CmdInj).
* `930100` — Path Traversal (LFI).
* `913100` — Scanner Detection (User-Agent).
* `949110` — Inbound Anomaly Score Exceeded (Итоговая блокировка).

