import socket
import threading
import time

# port this fake SSH listens on (the "real" port attackers see)
LISTEN_PORT = 22

# filled in by handler.py on startup via set_port_map()
# { "real": port, "honeypot": port }
port_map = {}

# filled in by handler.py - set of whitelisted IPs that get real SSH
whitelist = set()


def set_port_map(real_port, honeypot_port):  # From handler.py
    global port_map
    port_map = {
        "real": real_port,
        "honeypot": honeypot_port
    }
    print(f"[fssh] port map set: whitelist→{real_port}, everyone else→{honeypot_port}")


def set_whitelist(ips):
    global whitelist
    whitelist = set(ips)
    print(f"[fssh] whitelist set: {whitelist}")


def get_target_port(src_ip):
    if src_ip in whitelist:
        return port_map.get("real")
    return port_map.get("honeypot")


def proxy(src_conn, target_port, src_ip):
    """forwards traffic between the client and whatever port we decided to send them to"""
    try:
        dst_conn = socket.create_connection(("127.0.0.1", target_port))
    except Exception as e:
        print(f"[fssh] couldn't connect to target port {target_port}: {e}")
        src_conn.close()
        return

    print(f"[fssh] {'WHITELIST' if src_ip in whitelist else 'ATTACKER'} {src_ip} → port {target_port}")

    def forward(a, b):
        try:
            while True:
                data = a.recv(4096)
                if not data:
                    break
                b.sendall(data)
        except:
            pass
        finally:
            a.close()
            b.close()

    # two threads - one for each direction of traffic
    threading.Thread(target=forward, args=(src_conn, dst_conn), daemon=True).start()
    threading.Thread(target=forward, args=(dst_conn, src_conn), daemon=True).start()


def handle_connection(conn, addr):
    src_ip = addr[0]

    # make sure we have a port map before doing anything
    if not port_map:
        print(f"[fssh] got connection from {src_ip} but port map isn't set yet, dropping")
        conn.close()
        return

    target_port = get_target_port(src_ip)
    if not target_port:
        print(f"[fssh] no target port for {src_ip}, dropping")
        conn.close()
        return

    # SSH is sensitive to banner/key-exchange integrity; pass through backend
    # bytes transparently instead of injecting a synthetic banner.
    proxy(conn, target_port, src_ip)


def start():
    if not port_map:
        print("[fssh] warning: starting without port map, call set_port_map() first")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    print(f"[fssh] fake SSH listening on port {LISTEN_PORT}")

    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[fssh] accept error: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()
    return server  # return so main.py can close it on cleanup


# test standalone
if __name__ == "__main__":
    # fake setup mimicking what handler.py will do on real startup
    set_port_map(real_port=47832, honeypot_port=2222)
    set_whitelist(["172.20.10.3"])  # loopback is whitelisted for local testing

    s = start()
    print("whitelisted IPs -> port 47832 (real SSH)")
    print("non-whitelisted IPs -> port 2222 (Cowrie)")
    print("test with: ssh -p 22 <this-host-lan-ip>")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[fssh] shutting down")
        s.close()
