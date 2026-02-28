import asyncio
from Defense_Solutions.base import BaseDefense


class SSHDefense(BaseDefense):
    service = "ssh"

    async def _do_ban(self, ip: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "iptables", "-A", "INPUT", "-s", ip,
            "-p", "tcp", "--dport", "22", "-j", "DROP",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return f"iptables: blocked {ip} on port 22"
