# Kali Linux (192.168.56.30)

## Роль
Машина атакующего для эмуляции угроз.

## Скрипты
- `attacks/attack_sqli.sh` — SQL-инъекции (6 типов)
- `attacks/attack_ddos.sh` — SYN/UDP/ICMP flood
- `attacks/attack_owasp.sh` — XSS, Command Injection, IDOR

## Запуск
Все скрипты запускаются на Kali, атакуют `victim` (192.168.56.20).
