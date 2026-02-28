import socket
import csv

# Common services file on Linux
services_file = "/etc/services"

port_list = []

with open(services_file, "r") as f:
    for line in f:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        service_name = parts[0]
        port_proto = parts[1]  # e.g., "22/tcp"
        port, proto = port_proto.split("/")
        port_list.append([service_name, proto, port])

# Save to CSV
with open("all_ports.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Service", "Protocol", "Port"])
    writer.writerows(port_list)

print("All standard ports saved to all_ports.csv")
