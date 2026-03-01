from Defense_Solutions.fport.redirector import PortRedirector

# SSH redirector - stalls 1.5s to give scanner.py time to fire events
ssh_redirector = PortRedirector(
    name="fssh",
    listen_port=22,
    banner=b"SSH-2.0-OpenSSH_9.6\r\n",
    stall_time=1.5,
)

# convenience functions so existing code doesn't break
set_port_map = lambda real, honeypot: ssh_redirector.set_port_map(real, honeypot)
set_whitelist = lambda ips: ssh_redirector.set_whitelist(ips)
start = lambda: ssh_redirector.start()


if __name__ == "__main__":
    import time

    ssh_redirector.set_port_map(real_port=47832, honeypot_port=2222)
    ssh_redirector.set_whitelist(["127.0.0.1"])

    s = ssh_redirector.start()
    print("127.0.0.1 -> port 47832 (real), anything else -> port 2222 (honeypot)")
    print("test with: ssh -p 22 127.0.0.1")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[fssh] shutting down")
        ssh_redirector.stop()
