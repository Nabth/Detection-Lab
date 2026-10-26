# Victim (192.168.56.20)

## Роль
Защищаемый хост: IDS, WAF, уязвимое веб-приложение, Wazuh Agent.

## Компоненты
- **Suricata** — L3/L4 IDS (`suricata/`)
- **WAF Coraza + Nginx** — L7 защита (`waf-coraza/`)
- **Wazuh Agent** — отправка логов (`wazuh-agent/`)
- **iptables + sysctl** — rate limiting и hardening (`network/`)
- **DVWA** — уязвимое веб-приложение (`target-dvwa/`)

## Развёртывание
См. `docs/deployment.md`.
