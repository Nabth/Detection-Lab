# Wazuh Server (192.168.56.10)

## Роль
SIEM-ядро лабораторного стенда: Manager, Indexer, Dashboard.

## Что в этой папке
- `wazuh/manager/local_rules.xml` — кастомные правила (Coraza, DDoS, Nginx)
- `wazuh/manager/ossec.conf` — конфиг менеджера (пока не вынесен, в работе)
- `wazuh/decoders/local_decoder.xml` — кастомный декодер для `srcip`

## Развёртывание
Установка Wazuh all-in-one выполняется скриптом официального установщика.
См. `docs/deployment.md`.
