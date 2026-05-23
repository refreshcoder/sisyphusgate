from __future__ import annotations

import socket


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        return (
            octets[0] == 10
            or (octets[0] == 172 and 16 <= octets[1] <= 31)
            or (octets[0] == 192 and octets[1] == 168)
            or octets[0] == 127
        )
    except (ValueError, IndexError):
        return False


def format_bytes(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes}B"
    if num_bytes < 1048576:
        return f"{num_bytes / 1024:.1f}KB"
    if num_bytes < 1073741824:
        return f"{num_bytes / 1048576:.1f}MB"
    return f"{num_bytes / 1073741824:.1f}GB"