#!/usr/bin/env bash
set -euo pipefail

echo "[*] Applying sysctl settings..."
sudo sysctl -w net.netfilter.nf_conntrack_max=262144
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sudo sysctl -w net.ipv4.tcp_synack_retries=2

# Создаем/очищаем СВОЮ цепочку (не трогая INPUT, FORWARD, DOCKER-USER)
sudo iptables -N CUSTOM_DDOS 2>/dev/null || sudo iptables -F CUSTOM_DDOS

echo "[*] Applying ICMP flood protection..."
sudo iptables -A CUSTOM_DDOS -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name icmp_limit --hashlimit-upto 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A CUSTOM_DDOS -p icmp --icmp-type echo-request -j DROP

echo "[*] Applying SYN flood protection..."
sudo iptables -A CUSTOM_DDOS -p tcp --syn -m hashlimit --hashlimit-name syn_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A CUSTOM_DDOS -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --syn -j DROP

echo "[*] Applying UDP flood protection..."
sudo iptables -A CUSTOM_DDOS -p udp -m hashlimit --hashlimit-name udp_limit --hashlimit-upto 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A CUSTOM_DDOS -p udp -j DROP

echo "[*] Applying ACK/RST flood protections..."
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags ACK ACK -m hashlimit --hashlimit-name ack_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags ACK ACK -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags RST RST -m hashlimit --hashlimit-name rst_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags RST RST -j DROP

echo "[*] Applying invalid TCP flags and LAND protection..."
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags ALL ALL -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags ALL FIN -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
sudo iptables -A CUSTOM_DDOS -p tcp --tcp-flags PSH,ACK PSH -j DROP
sudo iptables -A CUSTOM_DDOS -s 192.168.56.20 -d 192.168.56.20 -j DROP

# Идемпотентно вставляем цепочку в INPUT (если ещё не вставлена)
if ! sudo iptables -C INPUT -j CUSTOM_DDOS 2>/dev/null; then
    sudo iptables -I INPUT 1 -j CUSTOM_DDOS
fi

echo "[+] Custom DDOS chain applied without touching Docker/UFW rules."
