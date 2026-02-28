from scapy.all import sniff, ARP, TCP, IP
from collections import defaultdict
import time
import queue
import threading

# how many ARP requests from one IP before we care
ARP_THRESHOLD = 5
ARP_WINDOW = 10  # seconds

# how many different ports before we call it a sweep
SWEEP_THRESHOLD = 15
SWEEP_WINDOW = 10

# repeated hits on the same port = brute force
BRUTE_THRESHOLD = 10
BRUTE_WINDOW = 10

# don't fire the same event twice in a row for the same IP
COOLDOWN = 1

# filled in by main.py on startup
event_queue = None

# track what each IP has been doing
ip_activity = defaultdict(lambda: {
    "arp": [],
    "ports": [],
    "brute": defaultdict(list),
    "last_fired": {}
})

lock = threading.Lock()


def prune(lst, cutoff):
    return [x for x in lst if x[0] > cutoff]


def should_fire(ip, event_type):
    last = ip_activity[ip]["last_fired"].get(event_type, 0)
    if time.time() - last < COOLDOWN:
        return False
    ip_activity[ip]["last_fired"][event_type] = time.time()
    return True


def fire(event_type, src_ip, extra={}):
    event = {
        "type": event_type,
        "src_ip": src_ip,
        "timestamp": time.time(),
        **extra
    }
    print(f"[scanner] {event_type} from {src_ip}")
    if event_queue:
        event_queue.put(event)


def handle_packet(pkt):
    now = time.time()

    # arp scan detection
    if ARP in pkt and pkt[ARP].op == 1:  # op 1 = who-has (request)
        src = pkt[ARP].psrc
        with lock:
            activity = ip_activity[src]
            activity["arp"].append((now,))
            activity["arp"] = prune(activity["arp"], now - ARP_WINDOW)

            if len(activity["arp"]) >= ARP_THRESHOLD:
                if should_fire(src, "arp.scan"):
                    fire("arp.scan", src, {
                        "count": len(activity["arp"]),
                        "target": pkt[ARP].pdst
                    })

    # tcp stuff
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        with lock:
            activity = ip_activity[src]

            # track every port this ip touches
            activity["ports"].append((now, dport))
            activity["ports"] = prune(activity["ports"], now - SWEEP_WINDOW)
            distinct = set(p for _, p in activity["ports"])

            # port sweep
            if len(distinct) >= SWEEP_THRESHOLD:
                if should_fire(src, "port.sweep"):
                    fire("port.sweep", src, {
                        "ports": list(distinct),
                        "count": len(distinct)
                    })

            # brute force - same port over and over
            if "S" in flags and "A" not in flags:  # SYN only
                activity["brute"][dport].append((now,))
                activity["brute"][dport] = prune(activity["brute"][dport], now - BRUTE_WINDOW)

                if len(activity["brute"][dport]) >= BRUTE_THRESHOLD:
                    if should_fire(src, f"brute.{dport}"):
                        fire("brute.force", src, {
                            "port": dport,
                            "count": len(activity["brute"][dport])
                        })

            # always fire a connect event so the TUI can track it
            if "S" in flags and "A" not in flags:
                fire("connect.attempt", src, {"port": dport})


def start(interface, q):
    global event_queue
    event_queue = q
    t = threading.Thread(target=lambda: sniff(iface=interface, prn=handle_packet, store=False), daemon=True)
    t.start()
    print(f"[scanner] listening on {interface}")


if __name__ == "__main__":
    import sys
    q = queue.Queue()
    start(sys.argv[1] if len(sys.argv) > 1 else "eth0", q)
    while True:
        print(q.get())
