import queue
import time
import sys

from scanner import start as start_scanner
from Defense_Solutions.fport.redirector import PortRedirector
from Defense_Solutions.FTP.ftp import start as start_ftp_honeypot

# ── config ──────────────────────────────────────────────────────
INTERFACE = "eth0"

# IPs that should reach the real services instead of the honeypot
WHITELIST = [
    "127.0.0.1",
]

# real service ports (where legit users actually connect)
REAL_SSH_PORT = 47832
REAL_FTP_PORT = 48291

# honeypot ports
HONEYPOT_SSH_PORT = 2222
HONEYPOT_FTP_PORT = 2121

# ── event queue shared by all components ────────────────────────
events = queue.Queue()

# ── redirectors ─────────────────────────────────────────────────
ssh_redirector = PortRedirector(
    name="fssh",
    listen_port=22,
    banner=b"SSH-2.0-OpenSSH_9.6\r\n",
    stall_time=1.5,
)

ftp_redirector = PortRedirector(
    name="fftp",
    listen_port=21,
    banner=b"220 (vsFTPd 3.0.5)\r\n",
    stall_time=0,
)


def handle_event(event):
    """Process a single event from the queue."""
    etype = event.get("type", "unknown")
    src = event.get("src_ip", "?")

    if etype == "arp.scan":
        print(f"[!] ARP scan detected from {src} ({event.get('count')} requests)")
    elif etype == "port.sweep":
        print(f"[!] Port sweep from {src} ({event.get('count')} ports)")
    elif etype == "brute.force":
        print(f"[!] Brute force on port {event.get('port')} from {src} ({event.get('count')} attempts)")
    elif etype == "ftp.honeypot":
        print(f"[honey] {src} | {event.get('action')} | {event.get('detail', '')}")
    elif etype == "connect.attempt":
        pass  # high-volume, only useful for TUI later


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else INTERFACE

    print("=" * 50)
    print("  GhostWall - port-migration honeypot")
    print("=" * 50)

    # 1. start packet scanner
    print(f"\n[*] Starting scanner on {iface}")
    start_scanner(iface, events)

    # 2. start FTP honeypot (must be up before the redirector sends traffic)
    print("[*] Starting FTP honeypot")
    ftp_hp = start_ftp_honeypot(events)

    # 3. configure and start redirectors
    ssh_redirector.set_whitelist(WHITELIST)
    ssh_redirector.set_port_map(REAL_SSH_PORT, HONEYPOT_SSH_PORT)

    ftp_redirector.set_whitelist(WHITELIST)
    ftp_redirector.set_port_map(REAL_FTP_PORT, HONEYPOT_FTP_PORT)

    print("[*] Starting SSH redirector")
    ssh_srv = ssh_redirector.start()

    print("[*] Starting FTP redirector")
    ftp_srv = ftp_redirector.start()

    print("\n[+] GhostWall is running. Press Ctrl+C to stop.\n")

    # 4. event loop — process events as they arrive
    try:
        while True:
            try:
                event = events.get(timeout=1)
                handle_event(event)
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        ssh_redirector.stop()
        ftp_redirector.stop()
        ftp_hp.close()
        print("[*] GhostWall stopped.")


if __name__ == "__main__":
    main()
