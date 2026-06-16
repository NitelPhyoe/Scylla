from dataclasses import dataclass
from typing import Optional


@dataclass
class Protocol:
    name: str
    port: int
    requires_auth: bool
    description: str = ""


PROTOCOLS: dict[str, Protocol] = {
    "smb": Protocol(
        name="smb",
        port=445,
        requires_auth=False,
        description="SMB shares and admin access",
    ),
    "winrm": Protocol(
        name="winrm",
        port=5985,
        requires_auth=True,
        description="Remote PowerShell sessions",
    ),
    "rdp": Protocol(
        name="rdp",
        port=3389,
        requires_auth=False,
        description="Remote Desktop",
    ),
    "mssql": Protocol(
        name="mssql",
        port=1433,
        requires_auth=True,
        description="Microsoft SQL Server",
    ),
    "ldap": Protocol(
        name="ldap",
        port=389,
        requires_auth=False,
        description="LDAP directory queries",
    ),
    "ssh": Protocol(
        name="ssh",
        port=22,
        requires_auth=True,
        description="Secure Shell",
    ),
    "ftp": Protocol(
        name="ftp",
        port=21,
        requires_auth=False,
        description="File Transfer Protocol",
    ),
    "wmi": Protocol(
        name="wmi",
        port=135,
        requires_auth=True,
        description="Windows Management Instrumentation",
    ),
    "vnc": Protocol(
        name="vnc",
        port=5900,
        requires_auth=False,
        description="Virtual Network Computing",
    ),
    "nfs": Protocol(
        name="nfs",
        port=2049,
        requires_auth=False,
        description="Network File System",
    ),
}

DEFAULT_TIMEOUT = 15

PROTOCOL_COLORS: dict[str, str] = {
    "smb": "bright_yellow",
    "winrm": "bright_cyan",
    "rdp": "bright_blue",
    "mssql": "bright_magenta",
    "ldap": "bright_green",
    "ssh": "bright_white",
    "ftp": "yellow",
    "wmi": "cyan",
    "vnc": "blue",
    "nfs": "green",
}


def resolve_protocols(selected: Optional[list[str]] = None) -> list[Protocol]:
    if selected:
        invalid = set(selected) - set(PROTOCOLS)
        if invalid:
            msg = f"Unknown protocol(s): {', '.join(sorted(invalid))}"
            raise ValueError(msg)
        return [PROTOCOLS[name] for name in selected]
    return list(PROTOCOLS.values())