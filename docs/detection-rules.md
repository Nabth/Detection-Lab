# Матрица детектирования

| Атака | Инструмент | Правило WAF (CRS) | Правило Wazuh | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection** | curl / sqlmap | 942100 (libinjection) | 100102 (Level 12) | T1190 |
| **SYN Flood** | hping3 | N/A | (Будет добавлено) | T1498.001 |
| **Nmap Scan** | nmap | N/A | 86601 (Suricata default) | T1046 |
