from pathlib import Path
from analysis.parsers.suricata import parse_eve
from analysis.parsers.coraza import parse_coraza

if __name__ == "__main__":
    suricata_path = Path("/var/log/suricata/eve.json")
    if suricata_path.exists():
        suri_events = list(parse_eve(suricata_path))
        print(f"[+] Suricata: распарсено {len(suri_events)} событий.")
        for e in suri_events[:2]:
            print(f"  - {e.timestamp.strftime('%H:%M:%S')} | {e.attack_type.value.upper()} | {e.source_ip} -> {e.dest_ip}")
    else:
        print("[-] Файл eve.json не найден.")

    print("-" * 50)

    coraza_path = Path("/var/log/coraza/audit/audit.log")
    if coraza_path.exists():
        coraza_events = list(parse_coraza(coraza_path))
        print(f"[+] Coraza WAF: распарсено {len(coraza_events)} заблокированных событий.")
        for e in coraza_events[:2]:
            print(f"  - {e.timestamp.strftime('%H:%M:%S')} | {e.attack_type.value.upper()} | {e.source_ip} -> {e.dest_ip}")
    else:
        print("[-] Файл audit.log не найден.")
