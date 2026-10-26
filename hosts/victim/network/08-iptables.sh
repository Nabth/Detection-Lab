#!/usr/bin/env bash
set -euo pipefail

echo "[*] Applying sysctl settings (Production mode)..."
sudo sysctl -w net.netfilter.nf_conntrack_max=262144
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sudo sysctl -w net.ipv4.tcp_synack_retries=2

echo "[*] Flushing old iptables rules..."
sudo iptables -F
sudo iptables -X

echo "[*] Applying iptables SYN flood protection (Realistic)..."
sudo iptables -N SYN_FLOOD
sudo iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j SYN_FLOOD
# Разрешаем до 100 SYN/сек, burst 200
sudo iptables -A SYN_FLOOD -m hashlimit --hashlimit-name syn_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A SYN_FLOOD -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP
sudo iptables -A SYN_FLOOD -j DROP

echo "[*] Applying iptables UDP flood protection (Realistic)..."
sudo iptables -N UDP_FLOOD
sudo iptables -A INPUT -p udp -j UDP_FLOOD
# Разрешаем до 200 UDP/сек, burst 400
sudo iptables -A UDP_FLOOD -m hashlimit --hashlimit-name udp_limit --hashlimit-upto 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A UDP_FLOOD -j DROP

echo "[*] Applying iptables TCP flag anomaly protection..."
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

echo "[*] Restarting Docker to restore its iptables chains..."
sudo systemctl restart docker

echo "[+] iptables configured with realistic thresholds."

