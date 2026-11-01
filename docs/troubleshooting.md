# Troubleshooting: Реальные проблемы и их решения

Этот документ содержит описание проблем, с которыми я столкнулся при развертывании и эксплуатации лабораторного стенда, и способы их решения. Каждая проблема воспроизводима — можно развернуть стенд и проверить.

## 1. Ошибка установки Wazuh: No space left on device

**Симптом:** Скрипт установки Wazuh падает с `E: Write error - write (28: No space left on device)`. Скрипт автоматически откатывает установку.
**Причина:** 40 ГБ диска недостаточно для работы Wazuh Indexer (OpenSearch). Требуется минимум 60 ГБ.
**Решение:** Увеличить диск ВМ в VirtualBox до 60 ГБ и расширить LVM:
```bash
sudo apt install cloud-guest-utils -y
sudo growpart /dev/sda 3
sudo pvresize /dev/sda3
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
```

## 2. Агент Wazuh не подключается (version mismatch)

**Симптом:** В логах агента — `WARNING: Couldn't connect to server: 'Agent version must be lower or equal to manager version'`.
**Причина:** Репозиторий Ubuntu отдаёт Agent версии 4.14.9, а Manager был установлен версии 4.9.2.
**Решение:** Обновить весь стек до одной версии: `sudo apt-get install wazuh-indexer=4.14.9-1 wazuh-manager=4.14.9-1 wazuh-dashboard=4.14.9-1 -y`.

## 3. Синтаксическая ошибка в кастомных правилах Wazuh

**Симптом:** `wazuh-manager` в статусе `failed`. В логе — `CRITICAL: Error loading the rules: 'etc/rules/local_rules.xml'`.
**Причина:** Незакрытый тег `<group>` или неверный атрибут (например, использование тега `<order>`, который допустим только в декодерах).
**Решение:** Проверять конфиг перед рестартом: `sudo /var/ossec/bin/wazuh-analysisd -t`.

## 4. Active Response банит сам Wazuh Server

**Симптом:** Агент на `victim` теряет связь с Manager. В `iptables INPUT` на `victim` — `DROP` для IP `192.168.56.10`.
**Причина:** Wazuh Agent отправляет большой объём логов через TCP 1514. Suricata классифицирует всплеск ACK-пакетов как ACK Flood (правило `1000010`). Active Response банит IP Manager.
**Решение:** В Suricata добавлен файл `pass.rules` для игнорирования IP Wazuh Server. Также в `<global>` секции `ossec.conf` на Manager настроен whitelist: `<white_list>192.168.56.10</white_list>`.

## 5. Ошибка тега `<not_srcip>` в правилах Wazuh

**Симптом:** При добавлении `<not_srcip>192.168.56.10</not_srcip>` Manager выдает `CRITICAL: Invalid option 'not_srcip'`.
**Причина:** В Wazuh **нет** тега `<not_srcip>`.
**Решение:** Использовать `<field name="srcip" negate="yes">IP</field>` или глобальный whitelist.

## 6. Ошибка обновления правил Suricata (read operation timed out)

**Симптом:** `sudo suricata-update` зависает с `Error: Failed to copy file: The read operation timed out`.
**Причина:** Провайдер/маршрут режет скорость до `rules.emergingthreats.net`.
**Решение:** Скачать правила вручную с хоста и скопировать в ВМ, либо использовать зеркала.

## 7. Suricata не видит Nmap

**Симптом:** `nmap` с Kali отрабатывает, но в `eve.json` есть только `flow`, нет `alert`.
**Причина:** Переменная `HOME_NET` содержала всю подсеть `192.168.56.0/24`. Kali попадала в HOME_NET, поэтому правила не срабатывали.
**Решение:** В `/etc/suricata/suricata.yaml`: `HOME_NET: "[192.168.56.20/32]"` и `EXTERNAL_NET: "![192.168.56.20/32,192.168.56.10/32]"`.

## 8. Suricata не видит атаки на уровне L7 (TLS)

**Симптом:** При HTTPS Suricata видит только TLS-метаданные, но не пейлоад.
**Причина:** Suricata — пассивный IDS, inline TLS-дешифрование не поддерживается.
**Решение (архитектурное):** Разделение ответственности. Suricata = L3/L4, WAF (Coraza) = L7.

## 9. Ошибка монтирования файла в Docker (is a directory)

**Симптом:** Контейнер падает с ошибкой `failed to readfile: read /opt/coraza/config.d/override.conf: is a directory`.
**Причина:** Docker при монтировании (`-v`) не находит файл по указанному пути и автоматически создает директорию с таким именем.
**Решение:** Удалить созданную папку и перезапустить контейнер.

## 10. Ошибка WAF-контейнера: host.docker.internal not found

**Симптом:** `[emerg] host not found in upstream "host.docker.internal:8080"`.
**Причина:** Docker в Linux не резолвит этот домен по умолчанию (в отличие от Docker Desktop).
**Решение:** В `setup-waf.sh` добавлены флаги `--network waf-network --ip 172.28.0.2` и `--add-host=host.docker.internal:host-gateway`.

## 11. Ошибка прав доступа к логам WAF

**Симптом:** `mkdir: can't create directory '/var/log/coraza/audit/': Permission denied`.
**Причина:** Контейнер работает от другого GID, прав на директорию `/var/log/coraza` у него нет.
**Решение:** `sudo chown -R root:waf-logs /var/log/coraza` и запуск контейнера с флагом `--group-add 2001`.

## 12. Nginx не выдает 429 при Slowloris

**Симптом:** `slowhttptest` открывает 100 соединений, но в `access.log` только `499` и `408`.
**Причина:** `limit_conn` обрывает соединение на уровне TCP до формирования HTTP-ответа.
**Решение (архитектурное):** Это корректная работа защиты. Запросы обрываются по таймауту.

## 13. Race Condition: L3/L4 DDoS блокирует L7 HTTP Flood

**Симптом:** При HTTP Flood в Wazuh срабатывает только ACK Flood (`100205`), а правило `100300` (429) молчит.
**Причина:** Suricata на L3 видит всплеск пакетов, срабатывает Active Response и банит IP. Nginx (L7) не успевает получить запросы и выдать 429.
**Решение:** Это фича эшелонированной защиты. Сетевой уровень отбивает атаку быстрее.

## 14. Рассинхронизация UFW и Docker

**Симптом:** После `ufw reload` WAF перестаёт отвечать (Connection refused).
**Причина:** UFW не перечитывает правила для Docker при простом reload.
**Решение:** После каждого `ufw reload` обязательно выполнять `sudo systemctl restart docker`.

## 15. Фатальная ошибка: `iptables -F` на хосте с UFW

**Симптом:** После попытки сбросить баны через `iptables -F` пропадает SSH и вся сеть.
**Причина:** Команда `iptables -F` удаляет jump-правила UFW и Docker. UFW показывает статус Active, но его правила больше не применяются к трафику.
**Решение:** Никогда не используйте `iptables -F`. Снимайте баны точечно: `sudo iptables -D INPUT -s <IP> -j DROP`. Если сломали — перезагрузите ВМ.

## 16. Telegram-бот зависает при отправке

**Симптом:** `Read timed out` при отправке алерта через Cloudflare Worker.
**Причина:** Встроенный Python Wazuh имеет старые TLS-библиотеки, которые не могут установить соединение с Cloudflare.
**Решение:** Переписать скрипт на библиотеку `requests` и использовать системный Python (`/usr/bin/python3`) в скрипте-обертке.

## 17. Уведомления Nmap не приходят в Telegram

**Симптом:** В Wazuh Dashboard алерты `100203` есть, а в Telegram они не отправляются.
**Причина:** В конфиге интеграции стоит порог `<level>10</level>`, а правило `100203` имело уровень 7.
**Решение:** Поднять уровень правила `100203` в `local_rules.xml` до 10.

## 18. Зависание ВМ при DDoS (CPU Soft Lockup)

**Симптом:** ВМ полностью зависает при `hping3 --flood`. В консоли `watchdog: BUG: soft lockup`.
**Причина:** Виртуальный коммутатор VirtualBox не справляется с сотнями тысяч пакетов в секунду. Ядро Linux уходит в бесконечный цикл обработки прерываний.
**Решение:** Использовать контролируемый флуд в скриптах: `-i u200` (5000 пакетов/сек) и `-c 30000` вместо `--flood`.

## 19. NULL-сканирование не детектируется

**Симптом:** Пакеты NULL Scan (`hping3 -0`) отправляются с Kali, но Suricata их не видит.
**Причина:** Пакет с нулевыми флагами отбрасывается ядром Linux или виртуальным коммутатором до попадания в AF_PACKET (Suricata).
**Решение:** Ограничение виртуальной среды. В реальной сети пакеты доходят до IDS.

## 20. Проблема с DNS после Docker/UFW

**Симптом:** `git push` падает с `Could not resolve host: github.com`, но `ping 8.8.8.8` работает.
**Причина:** `systemd-resolved` сбрасывает `/etc/resolv.conf` после перезагрузки сетевых сервисов.
**Решение:** Вручную прописать nameserver: `sudo sh -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'` или отключить `systemd-resolved`.
