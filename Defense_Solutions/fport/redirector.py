import socket
import threading
import time


class PortRedirector:
    """
    Generic port redirector that routes connections based on IP whitelist.
    Whitelisted IPs go to the real service, everyone else goes to the honeypot.
    """

    def __init__(self, name, listen_port, banner, stall_time=0):
        self.name = name
        self.listen_port = listen_port
        self.banner = banner if isinstance(banner, bytes) else banner.encode()
        self.stall_time = stall_time
        self.port_map = {}
        self.whitelist = set()
        self.server = None

    def set_port_map(self, real_port, honeypot_port):
        self.port_map = {"real": real_port, "honeypot": honeypot_port}
        print(f"[{self.name}] port map set: whitelist->{real_port}, everyone else->{honeypot_port}")

    def set_whitelist(self, ips):
        self.whitelist = set(ips)
        print(f"[{self.name}] whitelist set: {self.whitelist}")

    def _get_target_port(self, src_ip):
        if src_ip in self.whitelist:
            return self.port_map.get("real")
        return self.port_map.get("honeypot")

    def _proxy(self, src_conn, target_port, src_ip):
        try:
            dst_conn = socket.create_connection(("127.0.0.1", target_port))
        except Exception as e:
            print(f"[{self.name}] couldn't connect to target port {target_port}: {e}")
            src_conn.close()
            return

        label = "WHITELIST" if src_ip in self.whitelist else "ATTACKER"
        print(f"[{self.name}] {label} {src_ip} -> port {target_port}")

        def forward(a, b):
            try:
                while True:
                    data = a.recv(4096)
                    if not data:
                        break
                    b.sendall(data)
            except Exception:
                pass
            finally:
                a.close()
                b.close()

        threading.Thread(target=forward, args=(src_conn, dst_conn), daemon=True).start()
        threading.Thread(target=forward, args=(dst_conn, src_conn), daemon=True).start()

    def _handle_connection(self, conn, addr):
        src_ip = addr[0]

        if not self.port_map:
            print(f"[{self.name}] got connection from {src_ip} but port map isn't set yet, dropping")
            conn.close()
            return

        target_port = self._get_target_port(src_ip)
        if not target_port:
            print(f"[{self.name}] no target port for {src_ip}, dropping")
            conn.close()
            return

        try:
            conn.sendall(self.banner)
        except Exception:
            conn.close()
            return

        if self.stall_time > 0:
            time.sleep(self.stall_time)

        self._proxy(conn, target_port, src_ip)

    def start(self):
        if not self.port_map:
            print(f"[{self.name}] warning: starting without port map, call set_port_map() first")

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.listen_port))
        self.server.listen(10)
        print(f"[{self.name}] listening on port {self.listen_port}")

        def accept_loop():
            while True:
                try:
                    conn, addr = self.server.accept()
                    threading.Thread(
                        target=self._handle_connection, args=(conn, addr), daemon=True
                    ).start()
                except Exception as e:
                    print(f"[{self.name}] accept error: {e}")

        threading.Thread(target=accept_loop, daemon=True).start()
        return self.server

    def stop(self):
        if self.server:
            self.server.close()
            print(f"[{self.name}] stopped")
