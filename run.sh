sudo DEFENSE_MODE=auto-block DEFENSE_FIREWALL_BACKEND=nftables FSSH_WHITELIST="172.20.10.3,127.0.0.1" FSSH_FORCE_HONEYPOT="172.20.10.3" venv/bin/python3 TUI/tui.py --interface wlp0s20f3 --listen-port 22 --real-ssh-port 47832 --cowrie-port 2222 --reset-blacklist

