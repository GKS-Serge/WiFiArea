import os
import time
import threading
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, session

load_dotenv()

import models
import network_utils
from firewall_engine import CUSTOM_DOMAIN, GATEWAY_IP, FirewallEngine

app = Flask(__name__)
# <--- CONFIGUREZ VOS PARAMÈTRES ICI
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

login_attempts = {}

@app.after_request
def disable_response_caching(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/ping")
def ping():
    return jsonify({"ok": True})


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET", "POST"])
def captive_portal():
    # Si tu ouvres http://admin.knights.local ou http://admin.knightwifi.local, direction l'Admin !
    host = request.host.lower()
    if host.startswith("admin."):
        return redirect(url_for("admin_dashboard"))

    client_ip = request.remote_addr
    client_mac = network_utils.get_mac_from_ip(client_ip)
    error = None
    req_sent = False

    if request.method == "GET":
        active_sessions = models.get_active_sessions()
        for s in active_sessions:
            macs = (s["mac_address"] or "").split(",")
            if client_mac in macs and s["used_bytes"] < s["quota_bytes"]:
                return redirect(url_for("client_status", code=s["code"]))

    if request.method == "POST":
        action_type = request.form.get("action_type", "login")

        if action_type == "request_ticket":
            client_name = request.form.get("client_name", "").strip()
            quota_mb = float(request.form.get("quota_mb", 300))
            max_devices = int(request.form.get("max_devices", 1))
            estimated_price = int(request.form.get("estimated_price", 100))

            if not client_mac:
                error = "Impossible d'identifier votre appareil. Reconnectez-vous au Wi-Fi."
            elif client_name and quota_mb >= 50:
                req_id = models.create_ticket_request(client_name, client_mac, client_ip, quota_mb, max_devices, estimated_price)
                session["pending_request_id"] = req_id
                req_sent = True
        else:
            code = request.form.get("code", "").strip()
            if not client_mac:
                error = "Appareil non identifié. Reconnectez-vous au Wi-Fi."
            else:
                success, message, voucher = models.authenticate_voucher(code, client_mac, client_ip)
                if success:
                    session.pop("pending_request_id", None)
                    return redirect(url_for("client_status", code=voucher["code"]))
                else:
                    error = message

    latest_req = models.get_latest_request_for_mac(client_mac)
    approved_unused_code = None
    if latest_req and latest_req["status"] == "approved" and latest_req["generated_code"]:
        conn = models.get_db_connection()
        v = conn.execute("SELECT status FROM vouchers WHERE code = ?", (latest_req["generated_code"],)).fetchone()
        conn.close()
        if v and v["status"] == "unused":
            approved_unused_code = latest_req["generated_code"]

    return render_template(
        "login.html",
        error=error,
        req_sent=req_sent,
        latest_req=latest_req,
        approved_unused_code=approved_unused_code,
        client_mac=client_mac,
        gateway_ip=GATEWAY_IP
    )

@app.route("/api/request-status")
def request_status():
    req_id = session.get("pending_request_id")
    ticket_request = models.get_request_by_id(req_id) if req_id is not None else None

    if ticket_request is None:
        client_mac = network_utils.get_mac_from_ip(request.remote_addr)
        ticket_request = models.get_latest_request_for_mac(client_mac)

    status = ticket_request["status"] if ticket_request else "none"
    code = ticket_request["generated_code"] if ticket_request and status == "approved" else None
    return jsonify({"status": status, "code": code})

@app.route("/status/<code>")
def client_status(code):
    client_ip = request.remote_addr
    client_mac = network_utils.get_mac_from_ip(client_ip)
    
    conn = models.get_db_connection()
    voucher = conn.execute("SELECT * FROM vouchers WHERE code = ?", (code.upper(),)).fetchone()
    conn.close()

    macs = (voucher["mac_address"] or "").split(",") if voucher else []
    if not voucher or client_mac not in macs or voucher["status"] != "active":
        return redirect(url_for("captive_portal"))

    used_mb = round(voucher["used_bytes"] / (1024 * 1024), 2)
    quota_mb = round(voucher["quota_bytes"] / (1024 * 1024), 2)
    remaining_mb = max(0, round(quota_mb - used_mb, 2))
    percent = min(100, round((voucher["used_bytes"] / voucher["quota_bytes"]) * 100, 1))

    return render_template(
        "status.html",
        voucher=dict(voucher),
        used_mb=used_mb,
        quota_mb=quota_mb,
        remaining_mb=remaining_mb,
        percent=percent
    )

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    client_ip = request.remote_addr
    now = time.time()
    record = login_attempts.get(client_ip, {"count": 0, "blocked_until": 0})

    if now < record["blocked_until"]:
        return render_template("admin_login.html", error=f"Bloqué. Réessayez dans {int(record['blocked_until'] - now)}s.")

    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            login_attempts.pop(client_ip, None)
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        record["count"] += 1
        if record["count"] >= 5:
            record["blocked_until"] = now + 60
        error = "Mot de passe incorrect."
        login_attempts[client_ip] = record

    return render_template("admin_login.html", error=error)

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    new_codes = []
    if request.method == "POST":
        count = min(50, max(1, int(request.form.get("count", 1))))
        quota_mb = max(5, float(request.form.get("quota_mb", 300)))
        max_devices = int(request.form.get("max_devices", 1))
        new_codes = models.create_vouchers(count, quota_mb, max_devices)

    vouchers = models.get_all_vouchers()
    pending_requests = models.get_pending_requests()
    stats = models.get_dashboard_stats()
    return render_template(
        "admin.html",
        vouchers=vouchers,
        pending_requests=pending_requests,
        stats=stats,
        new_codes=new_codes,
        format_bytes=network_utils.format_bytes,
        portal_url=f"http://{CUSTOM_DOMAIN}/"
    )

@app.route("/admin/request/<int:req_id>/<decision>")
@admin_required
def admin_request_decision(req_id, decision):
    if decision == "approve":
        models.approve_request(req_id)
    elif decision == "reject":
        models.reject_request(req_id)
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/action/<int:voucher_id>/<action>")
@admin_required
def admin_action(voucher_id, action):
    if action == "delete":
        models.delete_voucher(voucher_id)
    elif action in ("banned", "active", "unused"):
        models.update_voucher_status(voucher_id, action)
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/cleanup")
@admin_required
def admin_cleanup():
    models.delete_inactive_vouchers()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("captive_portal"))

def register_local_admin_domain(domains=("admin.knights.local", "admin.knightwifi.local")):
    """Enregistre automatiquement les domaines admin locaux dans Windows hosts au démarrage."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            content = f.read()
        missing = [d for d in domains if d not in content]
        if missing:
            with open(hosts_path, "a", encoding="utf-8") as f:
                f.write(f"\n127.0.0.1 {' '.join(missing)}\n")
    except Exception:
        pass

if __name__ == "__main__":
    register_local_admin_domain()
    models.init_db()
    firewall = FirewallEngine()
    threading.Thread(target=firewall.start_packet_filtering, daemon=True).start()
    print("==========================================================")
    print(f"  KNIGHT WIFI PORTAIL  : http://{CUSTOM_DOMAIN}")
    print("  DASHBOARD ADMIN      : http://admin.knights.local")
    print("==========================================================")
    app.run(host="0.0.0.0", port=80, debug=False)