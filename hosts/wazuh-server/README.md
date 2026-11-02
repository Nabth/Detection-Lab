# Wazuh Server (192.168.56.10)

## Роль
SIEM-ядро лабораторного стенда: Manager, Indexer и Dashboard. Отвечает за корреляцию событий, срабатывание Active Response и отправку уведомлений.

## Что в этой папке
*   `wazuh/manager/local_rules.xml` — Кастомные правила детектирования (для WAF, DDoS, Nginx) и настройки Active Response.
*   `wazuh/manager/ossec-manager.conf` — Главный конфиг менеджера. Включает whitelist (защита от самобана), правила AR и настройки интеграций.
*   `wazuh/manager/systemd-override.conf.example` — Шаблон для переменных окружения (токены Telegram).
*   `wazuh/decoders/local_decoder.xml` — Декодеры для корректного парсинга JSON-логов от Suricata и Coraza.
*   `wazuh/integrations/` — Скрипты для интеграции с Telegram. Включает Python-скрипт (с дедупликацией) и shell-обертку для запуска через системный Python.

## Развёртывание
Установка Wazuh all-in-one выполняется официальным установщиком. Подробная инструкция по настройке (и копированию конфигов из этого репозитория) описана в `docs/deployment.md`.
