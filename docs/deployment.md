# Развертывание стенда (Deployment Guide)

Инструкция по развертыванию SOC Detection Lab с нуля. Процесс разделен на **автоматизированные шаги** (скрипты из репозитория) и **ручную настройку** (там, где это требуется).

## Prerequisites

*   **Хост-система:** 16 ГБ RAM, 100 ГБ свободного места на диске.
*   **Гипервизор:** VirtualBox 7.x (или VMware Workstation).
*   **ISO-образы:** Ubuntu Server 22.04.5 LTS, Kali Linux 2024.x.

## Шаг 1: Настройка виртуальных машин

Создайте 3 ВМ со следующими характеристиками:

| ВМ | RAM | CPU | Диск | OS | Сеть |
|:---|:---|:---|:---|:---|:---|
| `wazuh-server` | 6 ГБ | 2 | 60 ГБ | Ubuntu Server 22.04 | Адаптер 1: NAT, Адаптер 2: Host-Only |
| `victim` | 2 ГБ | 2 | 20 ГБ | Ubuntu Server 22.04 | Адаптер 1: NAT, Адаптер 2: Host-Only |
| `kali` | 4 ГБ | 2 | 40 ГБ | Kali Linux | Адаптер 1: NAT, Адаптер 2: Host-Only |

**Важно:** Для адаптера Host-Only на машине `victim` установите тип адаптера «Неразборчивый режим» (Promiscuous Mode) = **Allow All**, иначе Suricata не увидит трафик.

## Шаг 2: Сетевая настройка и NTP

Настройте статические IP-адреса на Host-Only интерфейсе (`enp0s8`):
*   Wazuh Server: `192.168.56.10/24`
*   Victim: `192.168.56.20/24`
*   Kali: `192.168.56.30/24`

**На всех трех машинах** настройте синхронизацию времени (иначе алерты Wazuh будут с неверными метками времени):
```bash
sudo apt update && sudo apt install -y chrony
sudo systemctl enable --now chrony
```

## Шаг 3: Установка Wazuh Server

На машине `wazuh-server`:
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
*(Сохраните пароль от Dashboard, который выведется в конце установки).*
После установки настройте `ossec.conf` менеджера (правила, AR, интеграции). Готовый конфиг лежит в репозитории: `hosts/wazuh-server/wazuh/manager/ossec-manager.conf`.

## Шаг 4: Настройка Victim (Automated)

Склонируйте репозиторий на машину `victim`:
```bash
git clone https://github.com/Nabth/soc-detection-lab
cd ~/soc-detection-lab
```

Выполните автоматизированные скрипты (они настраивают сеть, фаервол и WAF):
```bash
# 1. Настройка iptables (CUSTOM_DDOS)
sudo ./hosts/victim/network/08-iptables.sh

# 2. Изоляция Docker
sudo ./hosts/victim/network/09-docker-user-hardening.sh

# 3. Генерация TLS-сертификатов для WAF
cd hosts/victim/waf-coraza
./gen_certs.sh
cd ~/soc-detection-lab

# 4. Запуск WAF в Docker
sudo ./hosts/victim/waf-coraza/setup-waf.sh
```

*(В скрипте `setup-waf.sh` уже заложены фиксы для правильной маршрутизации: сеть `waf-network` и флаг `--add-host=host.docker.internal:host-gateway`).*

## Шаг 5: Настройка Victim (Manual)

Установите веб-сервер и уязвимое приложение (DVWA):
```bash
sudo apt install -y apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php

# Перенос Apache на порт 8080
sudo sed -i 's/Listen 80/Listen 8080/g' /etc/apache2/ports.conf
sudo sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/g' /etc/apache2/sites-available/000-default.conf
sudo systemctl restart apache2

# Установка DVWA
sudo git clone https://github.com/digininja/DVWA.git /var/www/html/DVWA
sudo chown -R www-data:www-data /var/www/html/DVWA
sudo chmod 777 /var/www/html/DVWA/hackable/uploads/
sudo cp /var/www/html/DVWA/config/config.inc.php.dist /var/www/html/DVWA/config/config.inc.php

# Настройка MySQL
sudo mysql -e "CREATE DATABASE dvwa;"
sudo mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
sudo mysql -e "GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';"
```

Установите Fail2Ban (для защиты SSH):
```bash
sudo apt install -y fail2ban
# Настройте jail.local для sshd (bantime=1h, findtime=10m, maxretry=3)
sudo systemctl restart fail2ban
```

Настройте UFW (разрешите только нужные порты):
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 172.28.0.2 to any port 8080 proto tcp
sudo ufw --force enable
```

## Шаг 6: Настройка Wazuh Agent (Victim)

1. На `wazuh-server` сгенерируйте ключ для агента:
```bash
sudo /var/ossec/bin/manage_agents
# Выберите A (Add), введите имя "victum", IP 192.168.56.20.
# Выберите E (Extract key) и скопируйте ключ.
```

2. На `victim` установите и настройте агент:
```bash
sudo apt install -y wazuh-agent
sudo /var/ossec/bin/manage_agents
# Выберите I (Import key), вставьте ключ. Нажмите Q для выхода.

# Укажите IP менеджера в /var/ossec/etc/ossec.conf (<address>192.168.56.10</address>)
# Примените конфиг агента из репозитория:
sudo cp ~/soc-detection-lab/hosts/victim/wazuh-agent/ossec.conf /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

## Шаг 7: Верификация

На машине `victim` запустите проверку здоровья:
```bash
cd ~/soc-detection-lab
sudo ./tooling/health_check.sh
```
Все 7 сервисов должны быть в статусе `✓`.

На машине `kali` скопируйте скрипты атак и запустите симуляцию:
```bash
scp soc@192.168.56.20:~/soc-detection-lab/hosts/kali/attacks/*.sh ~/attacks/
cd ~/attacks && chmod +x *.sh
./run_all.sh
```
Проверьте Wazuh Dashboard (`https://192.168.56.10`) и Telegram (должны прийти уведомления).
