from pathlib import Path
from analysis.parsers.suricata import parse_eve

if __name__ == "__main__":
    # Укажи путь к eve.json (если он есть на victim)
    log_path = Path("/var/log/suricata/eve.json")
    
    if not log_path.exists():
        print(f"[-] Файл {log_path} не найден.")
        exit(1)
        
    events = list(parse_eve(log_path))
    print(f"[+] Успешно распарсено {len(events)} событий (алертов).")
    
    # Выведем первые 3 для проверки
    for e in events[:3]:
        print(f"  - {e.timestamp.strftime('%H:%M:%S')} | {e.attack_type.value.upper()} | {e.source_ip} -> {e.dest_ip} | {e.signature}")
