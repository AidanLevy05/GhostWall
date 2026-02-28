from Defense_Solutions.base import BaseDefense
from Defense_Solutions.ssh import SSHDefense
from Defense_Solutions.ftp import FTPDefense
from Defense_Solutions.telnet import TelnetDefense

_REGISTRY: dict[str, BaseDefense] = {
    "ssh":    SSHDefense(),
    "ftp":    FTPDefense(),
    "telnet": TelnetDefense(),
}


def get_defense(service: str) -> BaseDefense:
    return _REGISTRY.get(service, _REGISTRY["ssh"])
