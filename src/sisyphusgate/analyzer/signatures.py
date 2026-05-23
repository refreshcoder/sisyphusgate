from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Signature:
    name: str
    protocol: str
    pattern: str
    description: str = ""
    score: int = 30
    tags: list[str] = field(default_factory=list)

    def matches(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace")
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        except Exception:
            return False


DEFAULT_SIGNATURES: list[Signature] = [
    Signature(
        name="ssh_brute_force",
        protocol="ssh",
        pattern=r"^SSH-",
        description="SSH connection attempt",
        score=20,
        tags=["ssh", "scan"],
    ),
    Signature(
        name="http_path_scan_admin",
        protocol="http",
        pattern=r"(GET|POST|HEAD)\s+/(admin|wp-admin|administrator|manager)",
        description="Access to admin panel paths",
        score=40,
        tags=["http", "scan", "admin_access"],
    ),
    Signature(
        name="http_path_scan_env",
        protocol="http",
        pattern=r"(GET|POST|HEAD)\s+/\.env",
        description="Attempt to access .env file",
        score=50,
        tags=["http", "scan", "sensitive_file"],
    ),
    Signature(
        name="http_path_scan_config",
        protocol="http",
        pattern=r"(GET|POST|HEAD)\s+/(config|backup|dump|sql|db)",
        description="Access to config/backup paths",
        score=45,
        tags=["http", "scan", "sensitive_file"],
    ),
    Signature(
        name="http_sql_injection",
        protocol="http",
        pattern=r"(\bUNION\s+SELECT\b|\bSELECT\b.*\bFROM\b.*\bWHERE\b|'.*OR\s+'1'='1)",
        description="SQL injection attempt",
        score=70,
        tags=["http", "injection", "sql"],
    ),
    Signature(
        name="http_xss_attempt",
        protocol="http",
        pattern=r"(<script>|javascript:|onerror=|onload=|<img.*src=.*onerror)",
        description="XSS injection attempt",
        score=60,
        tags=["http", "injection", "xss"],
    ),
    Signature(
        name="http_scanner_ua",
        protocol="http",
        pattern=r"User-Agent:\s*(nmap|nikto|sqlmap|nessus|burpsuite|acunetix|gobuster|dirbuster)",
        description="Known scanner User-Agent",
        score=55,
        tags=["http", "scanner", "known_tool"],
    ),
    Signature(
        name="http_path_traversal",
        protocol="http",
        pattern=r"(\.\./|\.\.%2f|%2e%2e%2f|\.%00)",
        description="Path traversal attempt",
        score=65,
        tags=["http", "traversal"],
    ),
    Signature(
        name="telnet_connection",
        protocol="telnet",
        pattern=r".",
        description="Telnet connection attempt",
        score=15,
        tags=["telnet", "scan"],
    ),
    Signature(
        name="http_webshell_scan",
        protocol="http",
        pattern=r"(GET|POST)\s+/(cmd|shell|exec|upload)(\.(php|jsp|asp|aspx))?",
        description="Webshell path scan",
        score=60,
        tags=["http", "scan", "webshell"],
    ),
    Signature(
        name="http_wordpress_scan",
        protocol="http",
        pattern=r"(GET|POST)\s+/(wp-content|wp-includes|wp-login|xmlrpc)",
        description="WordPress specific scan",
        score=35,
        tags=["http", "scan", "wordpress"],
    ),
    Signature(
        name="http_phpmyadmin_scan",
        protocol="http",
        pattern=r"(GET|POST)\s+/(phpmyadmin|pma|mysql|phpMyAdmin)",
        description="phpMyAdmin scan attempt",
        score=40,
        tags=["http", "scan", "phpmyadmin"],
    ),
]


def load_signatures_from_file(filepath: str) -> list[Signature]:
    import json
    import os

    signatures = list(DEFAULT_SIGNATURES)

    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            data = json.load(f)
            for item in data:
                signatures.append(Signature(**item))

    return signatures