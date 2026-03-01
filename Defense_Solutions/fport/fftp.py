from Defense_Solutions.fport.redirector import PortRedirector

# FTP redirector - no stall, clients expect the banner immediately
ftp_redirector = PortRedirector(
    name="fftp",
    listen_port=21,
    banner=b"220 (vsFTPd 3.0.5)\r\n",
    stall_time=0,
)

# convenience functions so existing code doesn't break
set_port_map = lambda real, honeypot: ftp_redirector.set_port_map(real, honeypot)
set_whitelist = lambda ips: ftp_redirector.set_whitelist(ips)
start = lambda: ftp_redirector.start()


if __name__ == "__main__":
    import time

    ftp_redirector.set_port_map(real_port=48291, honeypot_port=2121)
    ftp_redirector.set_whitelist(["127.0.0.1"])

    s = ftp_redirector.start()
    print("127.0.0.1 -> port 48291 (real), anything else -> port 2121 (honeypot)")
    print("test with: ftp 127.0.0.1")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[fftp] shutting down")
        ftp_redirector.stop()
