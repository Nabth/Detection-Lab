# Scripts Reference: Полный справочник скриптов и файлов

В репозитории собраны файлы для настройки инфраструктуры, эмуляции атак и проверки состояния стенда. Документ структурирован по ролям (Red Team, Blue Team, SIEM и утилиты).

## 1. Red Team: Эмуляция атак (`hosts/kali/`)

**Назначение:** Скрипты для проверки защиты. Запускаются на машине атакующего (Kali Linux).
**Локальные файлы:**
*   `README.md` — Краткое описание роли машины.

**Скрипты атак:**
*   `attacks/run_all.sh` — Оркестратор. Запускает полную симуляцию (L3/L4, затем L7). Управляет паузами для снятия банов.
*   `attacks/attack_l34.sh` — Эмуляция DDoS (SYN, UDP, ICMP, ACK, RST) со спуфингом IP и сканирований (Nmap, XMAS, NULL).
*   `attacks/attack_l7.sh` — Эмуляция веб-атак (SQLi, XSS, CMD, LFI, обфускация) и HTTP Flood.

## 2. Blue Team: Защита и настройка (`hosts/victim/`)

**Назначение:** Скрипты конфигурации защищаемого хоста (Victim).
**Локальные файлы:**
*   `README.md` — Описание компонентов Victim.
*   `network/README.md` — Описание сетевых правил.

**Сетевые скрипты:**
*   `network/iptables-hardening.sh` — Создает цепочку `CUSTOM_DDOS` (rate limiting и блокировка невалидных TCP-флагов).
*   `network/docker-isolation.sh` — Настраивает цепочку `DOCKER-USER` (изоляция WAF-контейнера от остальной сети).
*   `setup-sync-time.sh` — Устанавливает NTP (chrony) для синхронизации времени.

**Конфиги Suricata:**
*   `suricata/custom.rules` — Кастомные правила детекта L3/L4.
*   `suricata/pass.rules` — Whitelist (игнорирование IP Wazuh Server).
*   `suricata/enable.conf` — Включение ET SCAN правил.
*   `suricata/suricata.yaml` — Главный конфиг IDS.

**Конфиги WAF (Coraza + Nginx):**
*   `waf-coraza/setup-waf.sh` — Скрипт запуска Docker-контейнера WAF.
*   `waf-coraza/gen_certs.sh` — Генерация TLS-сертификатов.
*   `waf-coraza/custom-nginx.conf` — Настройки rate-limit и security headers.
*   `waf-coraza/override.conf` — Кастомные правила WAF.

**Конфиг агента:**
*   `wazuh-agent/ossec.conf` — Настройка чтения логов.

## 3. SIEM: Правила и Интеграции (`hosts/wazuh-server/`)

**Назначение:** Настройки Wazuh Manager и скрипты интеграции.
**Локальные файлы:**
*   `README.md` — Описание роли сервера.

**Конфигурации менеджера:**
*   `wazuh/manager/local_rules.xml` — Кастомные правила детектирования и Active Response.
*   `wazuh/manager/ossec-manager.conf` — Главный конфиг (whitelist, AR, интеграции).
*   `wazuh/manager/systemd-override.conf.example` — Шаблон для переменных окружения.
*   `wazuh/decoders/local_decoder.xml` — Декодеры JSON-логов.

**Интеграция с Telegram:**
*   `wazuh/integrations/custom-telegram` — Shell-обертка (запускает системный Python).
*   `wazuh/integrations/custom-telegram.py` — Python-скрипт (форматирование, дедупликация, отправка).

## 4. Tooling: DevSecOps утилиты (`tooling/`)

**Назначение:** Вспомогательные скрипты для администратора стенда.
*   `health_check.sh` — Проверяет доступность 7 ключевых сервисов.
*   `reset_lab.sh` — Сбрасывает состояние стенда (снимает баны, перезапускает сервисы).
*   `correlate.sh` — Строит временной таймлайн атак по конкретному IP.
*   `flatten_json.py` — Преобразует вложенные JSON-логи в плоский CSV/TSV.
*   `requirements.txt` — Зависимости Python.

## 5. Документация (`docs/`)

*   `architecture.md` — Схема потоков данных и Defense in Depth.
*   `deployment.md` — Пошаговая инструкция по развертыванию.
*   `detection-rules.md` — Справочник правил Suricata, Wazuh, WAF.
*   `hardening.md` — Описание настроек iptables, Nginx, Docker, UFW.
*   `gap-analysis.md` — Честный анализ ограничений стенда.
*   `troubleshooting.md` — 20+ реальных проблем и их решения.
*   `testing.md` — Описание Health Check и процесса верификации.
*   `evidence.md` — Визуальные доказательства работы (скриншоты).
*   `scripts.md` — Этот справочник.
*   `images/` — Папка со скриншотами.
