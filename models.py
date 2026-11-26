import sqlite3
import secrets
from datetime import datetime

DB_PATH = "wifizone.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vouchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            quota_bytes INTEGER NOT NULL,
            used_bytes INTEGER DEFAULT 0,
            max_devices INTEGER DEFAULT 1,
            mac_address TEXT DEFAULT NULL,
            ip_address TEXT DEFAULT NULL,
            status TEXT DEFAULT 'unused',
            created_at TEXT NOT NULL,
            activated_at TEXT DEFAULT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT NOT NULL,
            mac_address TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            quota_mb REAL NOT NULL,
            max_devices INTEGER DEFAULT 1,
            estimated_price INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            generated_code TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Migration douce si l'ancienne table existe déjà sans max_devices
    try:
        cursor.execute("ALTER TABLE vouchers ADD COLUMN max_devices INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

def generate_voucher_code():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = ''.join(secrets.choice(alphabet) for _ in range(4))
    p2 = ''.join(secrets.choice(alphabet) for _ in range(4))
    return f"{p1}-{p2}"

def create_vouchers(count, quota_mb, max_devices=1):
    conn = get_db_connection()
    cursor = conn.cursor()
    quota_bytes = int(quota_mb * 1024 * 1024)
    created_codes = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for _ in range(count):
        while True:
            code = generate_voucher_code()
            try:
                cursor.execute(
                    "INSERT INTO vouchers (code, quota_bytes, max_devices, created_at) VALUES (?, ?, ?, ?)",
                    (code, quota_bytes, max_devices, now)
                )
                created_codes.append(code)
                break
            except sqlite3.IntegrityError:
                continue
                
    conn.commit()
    conn.close()
    return created_codes

def authenticate_voucher(code, mac_address, ip_address):
    code = code.strip().upper()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM vouchers WHERE code = ?", (code,))
    voucher = cursor.fetchone()
    
    if not voucher:
        conn.close()
        return False, "Code invalide ou inexistant.", None
        
    if voucher["status"] == "banned":
        conn.close()
        return False, "Ce code a été bloqué par l'administrateur.", None
        
    if voucher["status"] == "exhausted" or voucher["used_bytes"] >= voucher["quota_bytes"]:
        cursor.execute("UPDATE vouchers SET status = 'exhausted' WHERE id = ?", (voucher["id"],))
        conn.commit()
        conn.close()
        return False, "Forfait épuisé (0 Mo restant).", None

    max_dev = voucher["max_devices"] or 1
    mac_list = [m for m in (voucher["mac_address"] or "").split(",") if m]
    ip_list = [i for i in (voucher["ip_address"] or "").split(",") if i]

    # Déjà enregistré sur cet appareil -> mise à jour IP
    if mac_address in mac_list:
        idx = mac_list.index(mac_address)
        if idx < len(ip_list):
            ip_list[idx] = ip_address
        else:
            ip_list.append(ip_address)
        cursor.execute("UPDATE vouchers SET ip_address = ? WHERE id = ?", (",".join(ip_list), voucher["id"]))
        conn.commit()
        updated = dict(cursor.execute("SELECT * FROM vouchers WHERE id = ?", (voucher["id"],)).fetchone())
        conn.close()
        return True, "Session restaurée.", updated

    # Nouvel appareil -> vérifier s'il reste une place (1 ou 2 appareils)
    if len(mac_list) < max_dev:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mac_list.append(mac_address)
        ip_list.append(ip_address)
        act_time = voucher["activated_at"] or now
        cursor.execute("""
            UPDATE vouchers 
            SET mac_address = ?, ip_address = ?, status = 'active', activated_at = ?
            WHERE id = ?
        """, (",".join(mac_list), ",".join(ip_list), act_time, voucher["id"]))
        conn.commit()
        updated = dict(cursor.execute("SELECT * FROM vouchers WHERE id = ?", (voucher["id"],)).fetchone())
        conn.close()
        return True, "Connexion réussie !", updated

    conn.close()
    return False, f"Refusé : limite de {max_dev} appareil(s) déjà atteinte pour ce code.", None

def get_active_sessions():
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM vouchers WHERE status = 'active'").fetchall()]
    conn.close()
    return rows

def update_usage_batch(usage_map):
    if not usage_map:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    for voucher_id, added_bytes in usage_map.items():
        cursor.execute("""
            UPDATE vouchers 
            SET used_bytes = used_bytes + ?,
                status = CASE WHEN (used_bytes + ?) >= quota_bytes THEN 'exhausted' ELSE status END
            WHERE id = ? AND status = 'active'
        """, (added_bytes, added_bytes, voucher_id))
    conn.commit()
    conn.close()

def get_all_vouchers():
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM vouchers ORDER BY id DESC").fetchall()]
    conn.close()
    return rows

def update_voucher_status(voucher_id, new_status):
    conn = get_db_connection()
    conn.execute("UPDATE vouchers SET status = ? WHERE id = ?", (new_status, voucher_id))
    conn.commit()
    conn.close()

def delete_voucher(voucher_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM vouchers WHERE id = ?", (voucher_id,))
    conn.commit()
    conn.close()

def delete_inactive_vouchers():
    conn = get_db_connection()
    conn.execute("DELETE FROM vouchers WHERE status IN ('exhausted', 'banned')")
    conn.commit()
    conn.close()

def get_dashboard_stats():
    conn = get_db_connection()
    row = conn.execute("""
        SELECT 
            COUNT(*) as total_codes,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_users,
            SUM(CASE WHEN status = 'unused' THEN 1 ELSE 0 END) as available_codes,
            COALESCE(SUM(used_bytes), 0) as total_used_bytes,
            COALESCE(SUM(quota_bytes), 0) as total_quota_bytes
        FROM vouchers
    """).fetchone()
    conn.close()
    return dict(row)

# --- Gestion des demandes clients ---
def create_ticket_request(client_name, mac_address, ip_address, quota_mb, max_devices, estimated_price):
    conn = get_db_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Remplace une éventuelle ancienne demande en attente du même appareil
    conn.execute("DELETE FROM requests WHERE mac_address = ? AND status = 'pending'", (mac_address,))
    cursor = conn.execute("""
        INSERT INTO requests (client_name, mac_address, ip_address, quota_mb, max_devices, estimated_price, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (client_name, mac_address, ip_address, quota_mb, max_devices, estimated_price, now))
    req_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return req_id

def get_pending_requests():
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM requests WHERE status = 'pending' ORDER BY id DESC").fetchall()]
    conn.close()
    return rows

def get_latest_request_for_mac(mac_address):
    if not mac_address:
        return None
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM requests WHERE mac_address = ? ORDER BY id DESC LIMIT 1", (mac_address,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_request_by_id(req_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def approve_request(req_id):
    """Génère le code en statut 'unused' pour que le client le voie et le saisisse lui-même."""
    conn = get_db_connection()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()
    if req and req["status"] == "pending":
        codes = create_vouchers(1, req["quota_mb"], req["max_devices"])
        code = codes[0]
        conn.execute("UPDATE vouchers SET status = 'unused' WHERE code = ?", (code,))
        conn.execute("UPDATE requests SET status = 'approved', generated_code = ? WHERE id = ?", (code, req_id))
        conn.commit()
    conn.close()
    
def reject_request(req_id):
    conn = get_db_connection()
    conn.execute("UPDATE requests SET status = 'rejected' WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()