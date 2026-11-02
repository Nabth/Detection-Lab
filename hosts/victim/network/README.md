# Network Configuration (Victim)

Данная директория содержит скрипты и документацию для настройки сетевого периметра на машине Victim.

## 🛡️ UFW Rules

Стандартный файрвол UFW блокирует весь входящий трафик, кроме необходимых портов.

```bash
# Политика по умолчанию
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Разрешенные порты
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Доступ к Apache (DVWA) ТОЛЬКО из Docker-сети WAF
sudo ufw allow from 172.28.0.2 to any port 8080 proto tcp

sudo ufw enable
```

## 🐳 Docker Integration (`/etc/ufw/after.rules`)

Docker по умолчанию игнорирует правила UFW, создавая свои цепочки в обход `INPUT`. Чтобы изолировать контейнеры, правила прописываются в `after.rules` (применяются при `ufw reload`), либо накатываются скриптом `09-docker-user-hardening.sh`.

```text
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -p tcp --dport 443 -j RETURN
-A DOCKER-USER -p tcp --dport 80 -j RETURN
-A DOCKER-USER -s 172.28.0.2 -d 172.28.0.1 -p tcp --dport 8080 -j RETURN
-A DOCKER-USER -j DROP
```

## 🌐 Docker Network

Для работы WAF выделена отдельная подсеть с фиксированным IP-адресом (чтобы правила UFW и `DOCKER-USER` точно совпадали).

```bash
docker network create --subnet=172.28.0.0/24 --gateway=172.28.0.1 waf-network
```

## ⚠️ Важное предупреждение

**НИКОГДА не используйте `iptables -F` на этом хосте.**
Эта команда удалит jump-правила, созданные UFW (`ufw-before-input`) и Docker (`DOCKER-USER`). В результате `ufw status` будет показывать `active`, но сеть полностью перестанет работать (включая SSH).
Для снятия банов Active Response используйте только точечное удаление правил:

```text
sudo iptables -D INPUT -s <IP> -j DROP
sudo iptables -D FORWARD -s <IP> -j DROP
```
