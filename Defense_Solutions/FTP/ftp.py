import socket
import threading
import time

# this is where fftp.py sends attackers
# logs everything they do, keeps them engaged as long as possible
LISTEN_PORT = 2121

# fake filesystem they can "browse"
FAKE_FILES = [
    "backup_2024.tar.gz",
    "passwords_old.txt",
    "db_credentials.conf",
    "users.csv",
]

# filled in by main.py or handler.py so we can put events on the queue
event_queue = None

def set_event_queue(q):
    global event_queue
    event_queue = q


def log_event(src_ip, action, detail=""):
    entry = {
        "type": "ftp.honeypot",
        "src_ip": src_ip,
        "action": action,
        "detail": detail,
        "timestamp": time.time()
    }
    print(f"[ftp-honeypot] {src_ip} | {action} | {detail}")
    if event_queue:
        event_queue.put(entry)


def handle_session(conn, addr):
    src_ip = addr[0]
    log_event(src_ip, "connect")

    def send(msg):
        conn.sendall((msg + "\r\n").encode())

    # holds the passive data socket between PASV and LIST/RETR commands
    data_server = None

    try:
        send("220 (vsFTPd 3.0.5)")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            cmd = data.decode(errors="ignore").strip()
            if not cmd:
                continue

            parts = cmd.split(" ", 1)
            command = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            log_event(src_ip, "command", cmd)

            if command == "USER":
                send("331 Please specify the password.")

            elif command == "PASS":
                log_event(src_ip, "login_attempt", arg)
                send("230 Login successful.")

            elif command == "SYST":
                send("215 UNIX Type: L8")

            elif command == "PWD":
                send('257 "/" is the current directory')

            elif command == "CWD":
                send("250 Directory successfully changed.")

            elif command == "TYPE":
                send("200 Switching to Binary mode.")

            elif command == "PASV":
                # spin up a real temp socket so the client's data connection works
                if data_server:
                    data_server.close()
                data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_server.bind(("127.0.0.1", 0))  # OS picks a free port
                data_server.listen(1)
                data_port = data_server.getsockname()[1]
                p1, p2 = data_port >> 8, data_port & 0xFF
                send(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2}).")

            elif command == "LIST" or command == "NLST":
                if not data_server:
                    send("425 Use PASV or PORT first.")
                    continue
                send("150 Here comes the directory listing.")
                try:
                    data_conn, _ = data_server.accept()
                    listing = "\r\n".join(
                        f"-rw-r--r-- 1 root root 4096 Jan 01 00:00 {f}" for f in FAKE_FILES
                    ) + "\r\n"
                    data_conn.sendall(listing.encode())
                    data_conn.close()
                except Exception as e:
                    print(f"[ftp-honeypot] LIST data error: {e}")
                finally:
                    data_server.close()
                    data_server = None
                send("226 Directory send OK.")

            elif command == "RETR":
                log_event(src_ip, "file_download_attempt", arg)
                send("150 Opening BINARY mode data connection.")
                time.sleep(2)  # stall - waste their time
                send("425 Failed to establish connection.")
                if data_server:
                    data_server.close()
                    data_server = None

            elif command == "STOR":
                log_event(src_ip, "file_upload_attempt", arg)
                send("550 Permission denied.")

            elif command == "QUIT":
                send("221 Goodbye.")
                break

            else:
                send("500 Unknown command.")

    except Exception as e:
        print(f"[ftp-honeypot] session error {src_ip}: {e}")
    finally:
        if data_server:
            data_server.close()
        log_event(src_ip, "disconnect")
        conn.close()


def start(q=None):
    if q:
        set_event_queue(q)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    print(f"[ftp-honeypot] listening on port {LISTEN_PORT}")

    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_session, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[ftp-honeypot] accept error: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()
    return server


if __name__ == "__main__":
    import queue
    q = queue.Queue()
    s = start(q)
    print("honeypot FTP running on port 2121")
    print("test with: ftp 127.0.0.1 2121")

    try:
        while True:
            print(q.get())
    except KeyboardInterrupt:
        print("\n[ftp-honeypot] shutting down")
        s.close()
