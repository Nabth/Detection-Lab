# Архитектура лабораторного стенда

## Компоненты и сеть
- **Wazuh Server (192.168.56.10):** SIEM (Manager, Indexer, Dashboard).
- **Victim (192.168.56.20):** Wazuh Agent, Suricata (IDS), DVWA (LAMP), Coraza WAF (Docker/Nginx).
- **Attacker (Kali, 192.168.56.30):** Машина для эмуляции атак.

## Потоки данных и эшелонированная защита (Defense in Depth)
1. **Уровень L7 (Веб-приложения):** Клиент (Kali) -> `HTTPS:443` -> Coraza WAF (Nginx + OWASP CRS). WAF выполняет **терминацию TLS**, расшифровывает трафик, инспектирует пейлоад (SQLi, XSS) и проксирует очищенный трафик на `HTTP:80` -> Apache/DVWA.
2. **Уровень L3/L4 (Сети):** Suricata работает в режиме IDS на интерфейсе `enp0s8`. Она детектирует сетевые аномалии (SYN-flood, nmap-сканирования). Для HTTPS-трафика Suricata анализирует **только метаданные TLS-рукопожатия** (JA3, SNI, версии протокола), но не имеет доступа к зашифрованному пейлоаду.
3. **Сбор логов:** Wazuh Agent на Victim читает `eve.json` (Suricata) и `audit.log` (Coraza WAF) и отправляет их на Wazuh Manager по порту 1514 для корреляции.
