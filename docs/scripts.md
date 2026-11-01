Scripts Reference: Скрипты и автоматизация
В репозитории собраны скрипты для трех основных задач: эмуляция атак (Red Team), проверка работоспособности стенда (Blue Team/DevSecOps) и интеграция с внешними системами (Tooling).

🦹 Red Team: Скрипты атак (hosts/kali/attacks/)
Запускаются на машине атакующего (Kali Linux). Предназначены для проверки правил детектирования и работы Active Response.

Оркестратор run_all.sh
Главный скрипт, запускающий полную симуляцию. Управляет паузами для снятия банов.

PHASE 1 (L3/L4) — запускает attack_l34.sh. Использует спуфинг IP, чтобы проверить Suricata и Active Response, не блокируя реальный IP Kali.

PHASE 2 (L7) — запускает attack_l7.sh. Использует реальный IP (нужен для TCP). Скрипт делает паузы, когда срабатывает защита, и просит оператора разблокировать IP на Victim.

Сетевые атаки attack_l34.sh
Эмулирует L3/L4 атаки. Для каждого вектора генерируется случайный IP-адрес.

DDoS: SYN, UDP, ICMP, ACK, RST Flood (с контролем скорости -i u200, чтобы не перегрузить CPU VirtualBox).

Сканирования: Nmap SYN Scan (реальный IP), XMAS, NULL, Invalid Flags (спуфинг).

Примечание: NULL Scan может не детектироваться из-за отбрасывания пустых пакетов ядром (см. Gap Analysis).

Веб-атаки attack_l7.sh
Эмулирует атаки на уровне HTTP/HTTPS.

OWASP Top 10: SQLi (5 типов), XSS, Command Injection, LFI.

WAF Evasion: Обфускация SQLi (UNION/**/), Double URL Encoding (%2527), SQLMap User-Agent.

HTTP Flood: 60 параллельных запросов curl (вызывает 429 от Nginx и бан через Active Response).

🛡️ Blue Team / DevSecOps: Проверка и тесты (tooling/, testing/)
Запускаются на машине Victim для контроля состояния защищенного хоста.

Проверка здоровья tooling/health_check.sh
Скрипт проверяет доступность 7 ключевых компонентов. Запускается с sudo.

WAF (HTTPS 443)

Apache/DVWA (HTTP 8080)

Suricata service

Wazuh Agent service

Docker container (coraza-waf)

iptables CUSTOM_DDOS chain

Fail2Ban service

Регрессионные тесты testing/run_tests.sh
Быстрая проверка 5 базовых сценариев защиты:

SQL Injection (403): WAF блокирует id=1' OR '1'='1.

XSS (403): WAF блокирует <script>alert(1)</script>.

Suricata (Nmap): Запускает nmap -sS и ищет алерт ET SCAN.

Nginx Rate Limiting (429): Отправляет 60 запросов и ждет сработку limit_req.

Wazuh (Алерты): Проверяет, что события появились в alerts.json.

🔧 Tooling: Интеграции и утилиты (tooling/)
custom-telegram.py: Скрипт для Wazuh Integration. Форматирует алерты (CWE, CVSS, MITRE), использует дедупликацию (Anti-Spam Cache) и отправляет уведомления в Telegram через Cloudflare Worker.

correlate.sh: Утилита для выгрузки таймлайна атак по конкретному IP-адресу из логов Wazuh.

flatten_json.py: Утилита для преобразования сложных JSON-логов Suricata/Coraza в плоский CSV/TSV формат (удобно для анализа в Excel).
