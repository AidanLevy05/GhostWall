import socket
import threading
import time
from typing import Any, Callable
from pathlib import Path

# port this fake SSH listens on (the "real" port attackers see)
LISTEN_PORT = 22

# filled in by handler.py on startup via set_port_map()
# { "real": port, "honeypot": port }
port_map = {}

# filled in by handler.py - set of whitelisted IPs that get real SSH
whitelist = set()
force_honeypot = set()
blacklist = set()
blacklist_file = Path("fssh_blacklist.txt")
log_callback: Callable[[dict[str, Any]], None] | None = None


def set_log_callback(callback: Callable[[dict[str, Any]], None] | None) -> None:
    global log_callback
    log_callback = callback


def set_blacklist_file(path: str | Path) -> None:
    global blacklist_file
    blacklist_file = Path(path)


def load_blacklist() -> None:
    global blacklist
    try:
        if not blacklist_file.exists():
            blacklist = set()
            return
        loaded: set[str] = set()
        with blacklist_file.open("r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    loaded.add(ip)
        blacklist = loaded
        _emit(
            f"[fssh] blacklist loaded: {len(blacklist)} IPs",
            {"type": "fssh.blacklist", "event": "loaded", "count": len(blacklist), "path": str(blacklist_file)},
        )
    except Exception as exc:
        _emit(
            f"[fssh] blacklist load failed: {exc}",
            {"type": "fssh.error", "error": f"blacklist_load_failed:{exc}", "path": str(blacklist_file)},
        )


def _save_blacklist() -> None:
    try:
        blacklist_file.parent.mkdir(parents=True, exist_ok=True)
        with blacklist_file.open("w", encoding="utf-8") as f:
            for ip in sorted(blacklist):
                f.write(ip + "\n")
    except Exception as exc:
        _emit(
            f"[fssh] blacklist save failed: {exc}",
            {"type": "fssh.error", "error": f"blacklist_save_failed:{exc}", "path": str(blacklist_file)},
        )


def clear_blacklist() -> None:
    global blacklist
    blacklist = set()
    _save_blacklist()
    _emit(
        "[fssh] blacklist cleared",
        {"type": "fssh.blacklist", "event": "cleared", "count": 0, "path": str(blacklist_file)},
    )


def add_to_blacklist(src_ip: str, reason: str = "honeypot_route") -> None:
    if src_ip in blacklist:
        return
    blacklist.add(src_ip)
    _save_blacklist()
    _emit(
        f"[fssh] blacklisted {src_ip} ({reason})",
        {
            "type": "fssh.blacklist",
            "event": "added",
            "src_ip": src_ip,
            "reason": reason,
            "count": len(blacklist),
            "path": str(blacklist_file),
        },
    )


def _emit(message: str, event: dict[str, Any] | None = None) -> None:
    payload = dict(event or {})
    payload.setdefault("type", "fssh.log")
    payload.setdefault("timestamp", time.time())
    payload.setdefault("message", message)
    if log_callback is not None:
        try:
            log_callback(payload)
        except Exception:
            pass
        return
    print(message)


def set_port_map(real_port, honeypot_port):  # From handler.py
    global port_map
    port_map = {
        "real": real_port,
        "honeypot": honeypot_port
    }
    _emit(
        f"[fssh] port map set: whitelist→{real_port}, everyone else→{honeypot_port}",
        {
            "type": "fssh.config",
            "port": LISTEN_PORT,
            "real_port": int(real_port),
            "honeypot_port": int(honeypot_port),
        },
    )


def set_whitelist(ips):
    global whitelist
    whitelist = set(ips)
    _emit(
        f"[fssh] whitelist set: {whitelist}",
        {
            "type": "fssh.config",
            "port": LISTEN_PORT,
            "whitelist": sorted(whitelist),
        },
    )


def set_force_honeypot(ips):
    global force_honeypot
    force_honeypot = set(ips)
    _emit(
        f"[fssh] force-honeypot set: {force_honeypot}",
        {
            "type": "fssh.config",
            "port": LISTEN_PORT,
            "force_honeypot": sorted(force_honeypot),
        },
    )


def get_target_port(src_ip):
    if src_ip in force_honeypot:
        return port_map.get("honeypot")
    if src_ip in whitelist:
        return port_map.get("real")
    return port_map.get("honeypot")


def proxy(src_conn, target_port, src_ip):
    """forwards traffic between the client and whatever port we decided to send them to"""
    try:
        dst_conn = socket.create_connection(("127.0.0.1", target_port))
    except Exception as e:
        _emit(
            f"[fssh] couldn't connect to target port {target_port}: {e}",
            {
                "type": "fssh.error",
                "src_ip": src_ip,
                "port": LISTEN_PORT,
                "target_port": int(target_port),
                "error": str(e),
            },
        )
        src_conn.close()
        return

    if src_ip in force_honeypot:
        route = "force_honeypot"
    elif src_ip in whitelist:
        route = "whitelist"
    else:
        route = "attacker"
    if route == "attacker":
        add_to_blacklist(src_ip, reason=route)
    _emit(
        f"[fssh] {route.upper()} {src_ip} → port {target_port}",
        {
            "type": "fssh.route",
            "src_ip": src_ip,
            "port": LISTEN_PORT,
            "target_port": int(target_port),
            "route": route,
        },
    )

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

    if src_ip in blacklist:
        _emit(
            f"[fssh] BLACKLIST DROP {src_ip}",
            {"type": "fssh.blacklist", "event": "drop", "src_ip": src_ip, "port": LISTEN_PORT},
        )
        conn.close()
        return

    # make sure we have a port map before doing anything
    if not port_map:
        _emit(
            f"[fssh] got connection from {src_ip} but port map isn't set yet, dropping",
            {"type": "fssh.error", "src_ip": src_ip, "port": LISTEN_PORT, "error": "missing_port_map"},
        )
        conn.close()
        return

    target_port = get_target_port(src_ip)
    if not target_port:
        _emit(
            f"[fssh] no target port for {src_ip}, dropping",
            {"type": "fssh.error", "src_ip": src_ip, "port": LISTEN_PORT, "error": "missing_target_port"},
        )
        conn.close()
        return

    # SSH is sensitive to banner/key-exchange integrity; pass through backend
    # bytes transparently instead of injecting a synthetic banner.
    proxy(conn, target_port, src_ip)


def start():
    if not port_map:
        _emit(
            "[fssh] warning: starting without port map, call set_port_map() first",
            {"type": "fssh.warn", "port": LISTEN_PORT},
        )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    _emit(
        f"[fssh] fake SSH listening on port {LISTEN_PORT}",
        {"type": "fssh.status", "port": LISTEN_PORT, "status": "listening"},
    )
    _emit(
        f"[fssh] blacklist active: {len(blacklist)} IPs",
        {"type": "fssh.blacklist", "event": "active", "count": len(blacklist), "path": str(blacklist_file)},
    )

    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                _emit(
                    f"[fssh] accept error: {e}",
                    {"type": "fssh.error", "port": LISTEN_PORT, "error": str(e)},
                )

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
