import shutil
import subprocess
import os
import socket

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
def get_free_ports(start=1024, end=MAX_PORT):
    FREE_PORTS = []
    for port in range(start, end+1):
        test_port_freedom(port)
    return FREE_PORTS

def switch_port(current_port_name, current_port_number):
    pass

def test_port_freedom(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False



FREE_PORTS = get_free_ports()
print(FREE_PORTS)



    
    
    
    
    
# THE PROGRAM MUST ONLY TOUCH "PORT_CONFIGS'
# BACKUP CONFIGS STAYS THE SAME AND WILL BE USED TO RESET PORT STATES AFTER OPERATION
PORT_CONFIGS = "~/../../etc/services"
BACKUP_CONFIGS = "~/../../etc/ssh/PORT_BACKUPS"