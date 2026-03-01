import socket
import threading

LISTEN_PORT = 21

# convincing vsftpd banner - one of the most common FTP servers
FTP_BANNER = b"220 (vsFTPd 3.0.5)\r\n"

# filled in by handler.py on startup
# { "real": port, "honeypot": port }
port_map = {}

# whitelisted IPs get real FTP, everyone else goes to honeypot
whitelist = set()


def set_port_map(real_port, honeypot_port):
    global port_map
    port_map = {"real": real_port, "honeypot": honeypot_port}
    print(f"[fftp] port map set: whitelist→{real_port}, everyone else→{honeypot_port}")


def set_whitelist(ips):
    global whitelist
    whitelist = set(ips)
    print(f"[fftp] whitelist set: {whitelist}")


def get_target_port(src_ip):
    if src_ip in whitelist:
        return port_map.get("real")
    return port_map.get("honeypot")


def proxy(src_conn, target_port, src_ip):
    try:
        dst_conn = socket.create_connection(("127.0.0.1", target_port))
    except Exception as e:
        print(f"[fftp] couldn't connect to target port {target_port}: {e}")
        src_conn.close()
        return

    print(f"[fftp] {'WHITELIST' if src_ip in whitelist else 'ATTACKER'} {src_ip} → port {target_port}")

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

    threading.Thread(target=forward, args=(src_conn, dst_conn), daemon=True).start()
    threading.Thread(target=forward, args=(dst_conn, src_conn), daemon=True).start()


def handle_connection(conn, addr):
    src_ip = addr[0]

    if not port_map:
        print(f"[fftp] got connection from {src_ip} but port map isn't set yet, dropping")
        conn.close()
        return

    target_port = get_target_port(src_ip)
    if not target_port:
        print(f"[fftp] no target port for {src_ip}, dropping")
        conn.close()
        return

    try:
        conn.sendall(FTP_BANNER)
    except:
        conn.close()
        return

    # no stall - FTP clients expect the banner and immediately send USER
    # a delay here would look suspicious
    proxy(conn, target_port, src_ip)


def start():
    if not port_map:
        print("[fftp] warning: starting without port map, call set_port_map() first")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    print(f"[fftp] fake FTP listening on port {LISTEN_PORT}")

    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[fftp] accept error: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()
    return server


# if __name__ == "__main__":
#     set_port_map(real_port=48291, honeypot_port=2121)
#     set_whitelist(["127.0.0.1"])

#     s = start()
#     print("test with: ftp 127.0.0.1")
#     print("127.0.0.1 → port 48291 (real), anything else → port 2121 (honeypot)")

#     import time
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         print("\n[fftp] shutting down")
#         s.close()