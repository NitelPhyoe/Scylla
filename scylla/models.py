from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProtocolStatus(Enum):
    AUTHENTICATED = "authenticated"
    OPEN = "open"
    CLOSED = "closed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class Target:
    host: str
    port: Optional[int] = None

    def __str__(self) -> str:
        return self.host


@dataclass
class Credential:
    username: str
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None

    @property
    def has_auth(self) -> bool:
        return self.password is not None or self.ntlm_hash is not None

    @classmethod
    def from_line(cls, line: str) -> "Credential":
        parts = line.strip().split(":", 1)
        if len(parts) == 2:
            return cls(username=parts[0], password=parts[1])
        return cls(username=parts[0])

    def mask_password(self) -> str:
        if self.password:
            return f"{self.username}:{self.password}"
        if self.ntlm_hash:
            return f"{self.username}:{self.ntlm_hash[:24]}..."
        return self.username


@dataclass
class SweepResult:
    target: Target
    credential: Credential
    protocol: str
    status: ProtocolStatus
    detail: str = ""
    raw_output: str = ""

    @property
    def success(self) -> bool:
        return self.status in (ProtocolStatus.AUTHENTICATED, ProtocolStatus.OPEN)

    @property
    def access_level(self) -> str:
        return "Admin" if "Pwn3d!" in self.raw_output else ""