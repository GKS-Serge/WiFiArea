import subprocess
import re

def get_mac_from_ip(ip_address):
    """
    Lit la table ARP de Windows pour trouver l'adresse MAC associée à une IP locale.
    Retourne l'adresse MAC en majuscules (ex: 'AA-BB-CC-DD-EE-FF') ou None.
    """
    # Si test en local sur le PC lui-même
    if ip_address in ("127.0.0.1", "192.168.137.1"):
        return "LOCAL-HOST-PC"

    try:
        # Exécute 'arp -a <ip>' sous Windows
        output = subprocess.check_output(
            ["arp", "-a", ip_address],
            stderr=subprocess.DEVNULL,
            text=True
        )
        
        # Recherche le motif d'une adresse MAC Windows (xx-xx-xx-xx-xx-xx)
        match = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", output)
        if match:
            return match.group(1).upper()
            
    except Exception as e:
        print(f"[Erreur ARP] Impossible de lire la MAC pour {ip_address}: {e}")
        
    return None

def format_bytes(size_bytes):
    """Convertit des octets en format lisible (Ko, Mo, Go)."""
    if size_bytes < 1024:
        return f"{size_bytes} o"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} Ko"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} Mo"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} Go"