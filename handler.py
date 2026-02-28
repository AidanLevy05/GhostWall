import shutil
import subprocess
import os
import socket
import random

# Globals
MAX_PORT = 65535
PORT_SERVICES = {"ssh", "http", "ftp"}
FREE_PORTS = []

# Creates a port config file called "original_port_config.txt" with the format <name> <number>
def create_port_config_backup():
    service_port_map = dict()

    for service in PORT_SERVICES:
        port = socket.getservbyname( service, "tcp")
        service_port_map[ service ] = port

    with open("original_port_config.txt", "w", encoding="utf-8") as file:
        for name, number in service_port_map.items():
            file.writelines(f"{name} {number}\n")

# Reverts to original config settings for testing safety
def revert_port_config():
    for service in PORT_SERVICES:
        # with SSH handler imported earlier. import ssh_handler as ssh
        # revert to config original
        pass

# To be repeated after port movement
# (-1,-1) designates error
def get_free_ports(start=1024, end=MAX_PORT):
    FREE_PORTS = []
    for port in range(start, end+1):
        test_port_freedom(port)
    return FREE_PORTS

def switch_port(original_port, free_port_1, free_port_2):
    if(len(FREE_PORTS)>=2):
        real = random.choice(FREE_PORTS)
        FREE_PORTS.remove(real)
        fake = random.choice(FREE_PORTS)
        FREE_PORTS.remove(fake)
        return (real,fake)
    else:
        return(-1,-1)

def test_port_freedom(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False