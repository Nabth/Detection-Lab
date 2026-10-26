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

echo "[*] Applying ICMP flood protection..."
sudo iptables -N ICMP_FLOOD
sudo iptables -I INPUT 1 -p icmp --icmp-type echo-request -j ICMP_FLOOD
sudo iptables -A ICMP_FLOOD -m hashlimit --hashlimit-name icmp_limit --hashlimit-upto 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A ICMP_FLOOD -j DROP

echo "[*] Applying SYN flood protection..."
sudo iptables -N SYN_FLOOD
sudo iptables -I INPUT 1 -p tcp --syn -m conntrack --ctstate NEW -j SYN_FLOOD
sudo iptables -A SYN_FLOOD -m hashlimit --hashlimit-name syn_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A SYN_FLOOD -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP
sudo iptables -A SYN_FLOOD -j DROP

echo "[*] Applying UDP flood protection..."
sudo iptables -N UDP_FLOOD
sudo iptables -I INPUT 1 -p udp -j UDP_FLOOD
sudo iptables -A UDP_FLOOD -m hashlimit --hashlimit-name udp_limit --hashlimit-upto 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A UDP_FLOOD -j DROP

echo "[*] Applying ACK/RST flood protections..."
sudo iptables -N ACK_FLOOD
sudo iptables -I INPUT 1 -p tcp --tcp-flags ACK ACK -j ACK_FLOOD
sudo iptables -A ACK_FLOOD -m hashlimit --hashlimit-name ack_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A ACK_FLOOD -j DROP

sudo iptables -N RST_FLOOD
sudo iptables -I INPUT 1 -p tcp --tcp-flags RST RST -j RST_FLOOD
sudo iptables -A RST_FLOOD -m hashlimit --hashlimit-name rst_limit --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-srcmask 32 -j RETURN
sudo iptables -A RST_FLOOD -j DROP

echo "[*] Applying invalid TCP flags and LAND attack protection..."
sudo iptables -I INPUT 1 -p tcp --tcp-flags ALL NONE -j DROP       # NULL Scan
sudo iptables -I INPUT 1 -p tcp --tcp-flags ALL ALL -j DROP        # XMAS Scan
sudo iptables -I INPUT 1 -p tcp --tcp-flags ALL FIN -j DROP        # FIN Scan
sudo iptables -I INPUT 1 -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP # Invalid SYN+FIN
sudo iptables -I INPUT 1 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP # Invalid SYN+RST
sudo iptables -I INPUT 1 -p tcp --tcp-flags PSH,ACK PSH -j DROP     # Invalid PSH without ACK
sudo iptables -I INPUT 1 -s 192.168.56.20 -d 192.168.56.20 -j DROP  # LAND Attack

echo "[*] Restarting Docker to restore its iptables chains..."
sudo systemctl restart docker

echo "[+] iptables configured successfully."
