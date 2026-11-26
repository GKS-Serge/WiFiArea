import time
import os
import socket
import threading
import pydivert
import models

# <--- CONFIGUREZ VOTRE DOMAINE LOCAL ICI
HOTSPOT_SUBNET = "192.168.137."
GATEWAY_IP = "192.168.137.1"
CUSTOM_DOMAIN = os.environ.get("CUSTOM_DOMAIN", "knightwifi.local").strip().lower()
CUSTOM_DOMAIN_LABEL = CUSTOM_DOMAIN.partition(".")[0]
CUSTOM_DOMAIN_KEYWORDS = (
    (CUSTOM_DOMAIN_LABEL.encode("idna"),) if CUSTOM_DOMAIN_LABEL else ()
)
ALLOWED_TTLS = {64, 128}

class FirewallEngine:
    def __init__(self):
        self.running = False
        self.authorized_ips = {}
        self.usage_buffer = {}
        self.lock = threading.Lock()

    def sync_with_db(self):
        while self.running:
            time.sleep(2)
            with self.lock:
                usage_to_save = dict(self.usage_buffer)
                self.usage_buffer.clear()
                
            if usage_to_save:
                models.update_usage_batch(usage_to_save)
                
            active_sessions = models.get_active_sessions()
            new_auth_map = {}
            
            for session in active_sessions:
                remaining = session["quota_bytes"] - session["used_bytes"]
                if session["ip_address"] and remaining > 0:
                    ips = [ip.strip() for ip in session["ip_address"].split(",") if ip.strip()]
                    shared_session_obj = {
                        "id": session["id"],
                        "code": session["code"],
                        "remaining_bytes": remaining
                    }
                    for ip in ips:
                        new_auth_map[ip] = shared_session_obj
                    
            with self.lock:
                self.authorized_ips = new_auth_map

    def _build_local_dns_reply(self, packet):
        """Renvoie la passerelle locale pour les requêtes DNS du domaine configuré."""
        try:
            dns_query = bytes(packet.udp.payload)
            if len(dns_query) < 12:
                return None

            transaction_id = dns_query[:2]
            flags = b'\x81\x80'
            qdcount = dns_query[4:6]
            ancount = qdcount
            nscount = b'\x00\x00'
            arcount = b'\x00\x00'
            query_body = dns_query[12:]
            answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04' + socket.inet_aton(GATEWAY_IP)
            dns_response = transaction_id + flags + qdcount + ancount + nscount + arcount + query_body + answer

            resp_pkt = pydivert.Packet(
                raw=bytes(packet.raw),
                interface=packet.interface,
                direction=pydivert.Direction.INBOUND
            )
            resp_pkt.src_addr, resp_pkt.dst_addr = packet.dst_addr, packet.src_addr
            resp_pkt.src_port, resp_pkt.dst_port = packet.dst_port, packet.src_port
            resp_pkt.udp.payload = dns_response
            resp_pkt.recalculate_checksums()
            return resp_pkt
        except Exception:
            return None

    def _is_essential_local_traffic(self, packet):
        src = packet.src_addr
        dst = packet.dst_addr
        if src == GATEWAY_IP or dst == GATEWAY_IP:
            return True
        if packet.udp and (packet.src_port in (67, 68) or packet.dst_port in (67, 68)):
            return True
        if (packet.udp or packet.tcp) and (packet.src_port == 53 or packet.dst_port == 53):
            return True
        return False

    def _filter_loop(self, layer, layer_name):
        subnet_base = HOTSPOT_SUBNET.rstrip(".")
        bpf_filter = (
            f"ip and (ip.SrcAddr >= {subnet_base}.2 and ip.SrcAddr <= {subnet_base}.254 "
            f"or ip.DstAddr >= {subnet_base}.2 and ip.DstAddr <= {subnet_base}.254)"
        )
        try:
            with pydivert.WinDivert(bpf_filter, layer=layer) as w:
                print(f"[Moteur Réseau] Couche {layer_name} active sur {HOTSPOT_SUBNET}x")
                for packet in w:
                    if not self.running:
                        break

                    src = packet.src_addr
                    dst = packet.dst_addr
                    client_ip = src if src.startswith(HOTSPOT_SUBNET) else dst
                    is_outgoing_from_client = src.startswith(HOTSPOT_SUBNET)

                    # Les requêtes DNS du domaine configuré sont redirigées vers la passerelle locale.
                    if is_outgoing_from_client and packet.udp and packet.dst_port == 53:
                        dns_payload = bytes(packet.udp.payload).lower()
                        if any(keyword in dns_payload for keyword in CUSTOM_DOMAIN_KEYWORDS):
                            reply = self._build_local_dns_reply(packet)
                            if reply:
                                w.send(reply)
                                continue

                    if self._is_essential_local_traffic(packet):
                        w.send(packet)
                        continue

                    if is_outgoing_from_client:
                        if packet.ipv4.ttl not in ALLOWED_TTLS:
                            continue

                    packet_size = len(packet.raw)
                    allow_packet = False

                    with self.lock:
                        client_session = self.authorized_ips.get(client_ip)
                        if client_session and client_session["remaining_bytes"] > 0:
                            client_session["remaining_bytes"] -= packet_size
                            vid = client_session["id"]
                            self.usage_buffer[vid] = self.usage_buffer.get(vid, 0) + packet_size
                            allow_packet = True

                    if allow_packet:
                        w.send(packet)

        except PermissionError:
            print(f"[ERREUR CRITIQUE] Droits Administrateur requis pour {layer_name}.")
        except Exception as e:
            print(f"[Erreur {layer_name}] {e}")

    def start_packet_filtering(self):
        self.running = True
        threading.Thread(target=self.sync_with_db, daemon=True).start()
        threading.Thread(target=self._filter_loop, args=(pydivert.Layer.NETWORK, "NETWORK"), daemon=True).start()
        threading.Thread(target=self._filter_loop, args=(pydivert.Layer.NETWORK_FORWARD, "NETWORK_FORWARD"), daemon=True).start()
        while self.running:
            time.sleep(1)

    def stop(self):
        self.running = False