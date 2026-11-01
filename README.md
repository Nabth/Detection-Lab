# Detection Lab

> Изолированная лаборатория для эмуляции атак и валидации детекта на трёх уровнях: сеть (L3/L4), веб-приложение (L7) и SIEM-корреляция. Собрана по паттерну «IDS + WAF + SIEM + автоматическое реагирование» (Defense in Depth), типичному для реальных SOC.

![License](https://img.shields.io/badge/license-MIT-green)
![Wazuh](https://img.shields.io/badge/Wazuh-4.14.9-blue)
![Suricata](https://img.shields.io/badge/Suricata-8.0.7-orange)
![Coraza](https://img.shields.io/badge/Coraza_CRS-4.30_PL1-red)

---

## 🎯 Ключевая идея
Не просто развернуть инструменты, а **построить защиту, проверить её в бою** и честно задокументировать пробелы (Gap Analysis).

## 🏗️ Архитектура

```mermaid
flowchart LR
    subgraph ATTACKER["🦹 Attacker (Kali · 192.168.56.30)"]
        A1["hping3 · nmap · curl · sqlmap<br/>(с поддержкой спуфинга IP)"]
    end

    subgraph VICTIM["🛡️ Victim (192.168.56.20)"]
        direction TB
        FW["iptables<br/>CUSTOM_DDOS + DOCKER-USER + UFW"]
        SC["Suricata IDS<br/>passive sniff enp0s8"]
        NGX["nginx + Coraza WAF<br/>Docker waf-network 172.28.0.2 · :443"]
        AP["Apache + DVWA<br/>:8080"]
        WA["Wazuh Agent"]
    end

    subgraph SERVER["🧠 Wazuh Server (192.168.56.10)"]
        direction TB
        WM["Wazuh Manager<br/>rules + integrations"]
        WI["Wazuh Indexer<br/>(OpenSearch)"]
        WD["Wazuh Dashboard<br/>:443"]
        TG["Telegram Notifier<br/>(Cloudflare Worker)"]
    end

    A1 -->|"HTTPS :443 / DDoS / Scans"| FW
    FW -->|allowed| NGX
    SC -.->|"passive sniff (pass.rules для Wazuh)"| A1
    NGX -->|"proxy_pass"| AP

    WA -.->|"read eve.json"| SC
    WA -.->|"read error/access logs"| NGX
    WA -->|"TCP 1514"| WM
    WM --> WI --> WD
    WM -.->|"AR: firewall-drop"| WA
    WA -.->|"iptables DROP"| FW
    WM -.->|"alert level >= 10"| TG
```

## 📊 Покрытие детектирования (Detection Coverage)

| Атака | L3/L4 (iptables + Suricata) | L7 (WAF + Nginx) | SIEM (Wazuh) | Реакция (AR) | Статус |
|:---|:---:|:---:|:---:|:---:|:---:|
| **L3/L4 DDoS** (SYN/UDP/ICMP/ACK/RST) | ✅ Suricata Rules | — | `100200-100206` | ✅ 600s | 🟢 |
| **Сканирования** (Nmap/XMAS/NULL) | ✅ Suricata + ET SCAN | — | `100203, 100207` | ✅ 300s/600s | 🟢 |
| **OWASP Top 10** (SQLi, XSS, CmdInj) | — (TLS) | ✅ OWASP CRS | `100101, 100104` | — | 🟢 |
| **HTTP Flood** (429) | — | ✅ Nginx limit_req | `100300` (access.log) | ✅ 600s | 🟢 |
| **Slowloris / Timeout** | — | ✅ Nginx limit_conn | `100302` (error.log) | ✅ 600s | 🟡 (см. Gap) |
| **SSH Brute Force** | — | — | `5760` (sshd) | Fail2Ban | 🟢 |
| **TG Notifier** (Уведомления) | — | — | Wazuh Integration | — | 🟢 |

## 🧰 Стек технологий

| Слой | Инструмент | Версия |
|:---|:---|:---|
| SIEM | Wazuh (Manager + Indexer + Dashboard) | 4.14.9 |
| IDS (L3/L4) | Suricata + ET Open | 8.0.7 |
| WAF (L7) | OWASP Coraza + CRS | 4.30 PL1 |
| Reverse proxy | nginx (Docker, `waf-network`) | latest |
| Target | Apache + PHP 8.1 + MariaDB + DVWA | latest |
| SSH protection | Fail2Ban | 1.9 |
| Perimeter | iptables + UFW + DOCKER-USER | — |
| Notifier | Python + pyTelegramBotAPI + Cloudflare Worker | — |
| Attacker | hping3, nmap, sqlmap, hydra, slowhttptest | — |

## 🚀 Быстрый старт

1. **Развернуть 3 ВМ** — пошагово в [`docs/deployment.md`](docs/deployment.md).
2. **Проверить стенд** — `sudo ./tooling/health_check.sh` (все сервисы должны быть alive).
3. **Прогнать тесты** — `./hosts/kali/attacks/run_all.sh` (интерактивные скрипты атак).
4. **Открыть Dashboard** — `https://192.168.56.10` (Wazuh UI).

> ⚠️ Setup частично автоматизирован (`hosts/victim/network/*.sh`, `setup-waf.sh`), частично ручной (DVWA, Fail2Ban, UFW). **Точный split — в `docs/deployment.md`**.

## ⚠️ Известные ограничения (Gap Analysis)

Мы намеренно документируем слепые зоны, чтобы показать понимание архитектуры:
1. **Slowloris (HTTP/2 Gap):** Nginx настроен на HTTP/2 и отбивает невалидные HTTP/1.1 заголовки кодом `400` до срабатывания таймаута.
2. **Race Condition (L3 vs L7):** При HTTP Flood Suricata (L3) срабатывает быстрее и банит IP через Active Response, поэтому Nginx (L7) не успевает выдать 429.
3. **Fail2Ban Integration:** Логи банов не парсятся Wazuh (нет нативного декодера), хотя попытки SSH-логина Wazuh видит.
4. **NULL Scan (VirtualBox):** Пакеты с нулевыми флагами отбрасываются ядром гипервизора до Suricata.

Полный разбор → [`docs/gap-analysis.md`](docs/gap-analysis.md).

## 📚 Документация

*   [`docs/architecture.md`](docs/architecture.md) — Потоки данных и Defense in Depth.
*   [`docs/deployment.md`](docs/deployment.md) — Инструкция по развертыванию.
*   [`docs/detection-rules.md`](docs/detection-rules.md) — Кастомные правила Suricata, Wazuh, WAF.
*   [`docs/detection-matrix.md`](docs/detection-matrix.md) — Матрица покрытия атак.
*   [`docs/hardening.md`](docs/hardening.md) — Настройки iptables, Nginx, Docker, UFW.
*   [`docs/gap-analysis.md`](docs/gap-analysis.md) — Честный анализ ограничений.
*   [`docs/troubleshooting.md`](docs/troubleshooting.md) — 20+ реальных проблем и их решения.
*   [`docs/scripts.md`](docs/scripts.md) — Описание всех скриптов (Red Team, DevSecOps, Tooling).

## 📂 Структура репозитория

```text
├── hosts/                  # Конфиги по машинам (Wazuh, Victim, Kali)
├── docs/                   # Полная документация
├── testing/                # Bash test suite (run_tests.sh)
├── tooling/                # health_check, correlate, telegram_bot
└── README.md
```

## 📄 Лицензия
[MIT](LICENSE)
