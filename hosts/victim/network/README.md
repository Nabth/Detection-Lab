# Network Configuration (Victim)

## UFW Rules
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 172.28.0.2 to any port 8080 proto tcp

## /etc/ufw/after.rules (Docker Integration)
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -p tcp --dport 443 -j RETURN
-A DOCKER-USER -p tcp --dport 80 -j RETURN
-A DOCKER-USER -s 172.28.0.2 -d 172.28.0.1 -p tcp --dport 8080 -j RETURN
-A DOCKER-USER -j DROP

## Docker Network
docker network create --subnet=172.28.0.0/24 --gateway=172.28.0.1 waf-network

