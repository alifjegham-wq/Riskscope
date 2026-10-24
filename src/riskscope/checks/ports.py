"""Risky network services reachable from the internet (active: verified owners only).

A plain TCP connect to a short list of ports. No banners are grabbed and
nothing is sent, but it is still more than a normal visitor does, so it only
runs once the requester has proved they control the domain.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from ..models import Category, Finding, Severity
from ..safety import assert_public_host
from .base import ScanContext

CONNECT_TIMEOUT = 3.0

# port -> (service, severity, why)
RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "Sends passwords unencrypted."),
    22: ("SSH", Severity.INFO, "Fine if keys-only; make sure password login is disabled."),
    23: ("Telnet", Severity.HIGH, "Unencrypted remote login; a top target for botnets."),
    445: ("SMB", Severity.HIGH, "Windows file sharing; the entry point for WannaCry-style worms."),
    1433: ("Microsoft SQL Server", Severity.HIGH, "Databases should never face the internet."),
    2375: (
        "Docker API (no TLS)",
        Severity.CRITICAL,
        "Unauthenticated Docker API gives full control of the host.",
    ),
    3306: ("MySQL", Severity.HIGH, "Databases should never face the internet."),
    3389: (
        "Remote Desktop (RDP)",
        Severity.HIGH,
        "Constantly brute-forced; a common ransomware entry point.",
    ),
    5432: ("PostgreSQL", Severity.HIGH, "Databases should never face the internet."),
    5900: ("VNC", Severity.HIGH, "Remote screen access, often weakly protected."),
    6379: ("Redis", Severity.CRITICAL, "Redis has no authentication by default; trivially taken over."),
    8080: ("Alternate HTTP / admin panel", Severity.LOW, "Often an unprotected admin or staging service."),
    9200: ("Elasticsearch", Severity.CRITICAL, "Frequently left without auth, leaking whole datasets."),
    11211: ("Memcached", Severity.HIGH, "Unauthenticated; also abused for DDoS amplification."),
    27017: ("MongoDB", Severity.CRITICAL, "Frequently left without auth, leaking whole datasets."),
}

Connector = Callable[[str, int], Awaitable[bool]]


async def tcp_open(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
    except (OSError, TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


class OpenPortsCheck:
    name = "open_ports"
    title = "Risky services exposed to the internet"
    active = True

    def __init__(self, connect: Connector = tcp_open) -> None:
        self.connect = connect

    async def run(self, ctx: ScanContext) -> list[Finding]:
        ip = (await assert_public_host(ctx.target.host, ctx.fetcher.resolver))[0]
        ports = sorted(RISKY_PORTS)
        results = await asyncio.gather(*(self.connect(ip, p) for p in ports))
        out = []
        for port, is_open in zip(ports, results, strict=True):
            if not is_open:
                continue
            service, severity, why = RISKY_PORTS[port]
            out.append(
                Finding(
                    id=f"ports.{port}",
                    title=f"{service} (port {port}) is reachable from the internet",
                    severity=severity,
                    category=Category.NETWORK,
                    description=why,
                    evidence=f"TCP {ip}:{port} accepted a connection",
                    fix=(
                        f"Close port {port} in your firewall / security group, or restrict it to the specific "
                        "IPs or VPN that need it."
                    ),
                )
            )
        return out
