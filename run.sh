#!/bin/bash
IFACE=${1:-eth0}
sudo python3 main.py "$IFACE"
