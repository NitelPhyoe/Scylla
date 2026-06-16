import json
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .config import PROTOCOL_COLORS
from .models import ProtocolStatus, SweepResult


@dataclass
class _ProgressTracker:
    """Tracks per-protocol progress for live output."""

    total: int = 0
    done: int = 0
    statuses: dict[str, tuple[ProtocolStatus, Optional[SweepResult]]] = field(default_factory=dict)


STATUS_SYMBOLS = {
    ProtocolStatus.AUTHENTICATED: ("✓", "bold green"),
    ProtocolStatus.OPEN: ("●", "bold yellow"),
    ProtocolStatus.CLOSED: ("✗", "bold red"),
    ProtocolStatus.TIMEOUT: ("…", "dim white"),
    ProtocolStatus.ERROR: ("⚠", "bold red"),
    ProtocolStatus.SKIPPED: ("-", "dim white"),
}

STATUS_LABELS = {
    ProtocolStatus.AUTHENTICATED: "Authenticated",
    ProtocolStatus.OPEN: "Listening",
    ProtocolStatus.CLOSED: "Closed",
    ProtocolStatus.TIMEOUT: "Timed out",
    ProtocolStatus.ERROR: "Error",
    ProtocolStatus.SKIPPED: "Skipped",
}


def format_result(result: SweepResult, verbose: int = 0) -> Text:
    color = PROTOCOL_COLORS.get(result.protocol, "white")
    symbol, style = STATUS_SYMBOLS.get(result.status, ("?", "dim white"))
    label = STATUS_LABELS.get(result.status, "Unknown")

    t = Text()
    t.append(f"● ", style=f"bold {color}")
    t.append(f"{result.protocol.upper():<7}", style=f"bold {color}")
    t.append(f"{result.target.host:<16}", style="white")
    t.append(f"{result.credential.mask_password() if result.credential else '<no-auth>':<30}", style="dim")
    t.append(f" {symbol} ", style=style)
    t.append(f"{label}", style=style)

    if result.status == ProtocolStatus.AUTHENTICATED and result.access_level:
        t.append(f" [{result.access_level}]", style="bold green")
    elif result.detail and result.detail not in ("Listening", "No response"):
        if verbose > 0:
            t.append(f"  — ", style="dim")
            t.append(f"{result.detail}", style="dim white")

    return t


def build_summary(results: list[SweepResult]) -> str:
    accessed = sum(1 for r in results if r.success)
    total = len(results)
    return f"  {accessed}/{total} protocols accessible  "


def print_results(results: list[SweepResult], verbose: int = 0, output_json: bool = False) -> None:
    console = Console()

    if output_json:
        data = []
        for r in results:
            data.append({
                "protocol": r.protocol,
                "target": r.target.host,
                "username": r.credential.username if r.credential else None,
                "status": r.status.value,
                "detail": r.detail,
                "access_level": r.access_level,
            })
        console.print(json.dumps(data, indent=2))
        return

    for r in results:
        console.print(format_result(r, verbose=verbose))

    success_count = sum(1 for r in results if r.success)
    total = len(results)
    if success_count == 0:
        text = Text(f"  {success_count}/{total} protocols accessible", style="bold red")
    elif success_count == total:
        text = Text(f"  {success_count}/{total} all open! ", style="bold green")
    else:
        text = Text(f"  {success_count}/{total} protocols accessible", style="bold yellow")
    console.print()
    console.print(text)


def print_table(results: list[SweepResult], verbose: int = 0) -> None:
    """Alternative: render results as a Rich table."""
    console = Console()
    table = Table(box=None, show_header=False, padding=(0, 1))

    table.add_column("Icon", style="bold", no_wrap=True)
    table.add_column("Protocol", no_wrap=True)
    table.add_column("Target", no_wrap=True)
    table.add_column("Credential", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    if verbose > 0:
        table.add_column("Detail", no_wrap=True)

    for r in results:
        color = PROTOCOL_COLORS.get(r.protocol, "white")
        symbol, style = STATUS_SYMBOLS.get(r.status, ("?", "dim white"))
        label = STATUS_LABELS.get(r.status, "Unknown")
        cred_str = r.credential.mask_password() if r.credential else "<no-auth>"

        row = [
            Text("●", style=f"bold {color}"),
            Text(r.protocol.upper(), style=f"bold {color}"),
            Text(r.target.host, style="white"),
            Text(cred_str, style="dim"),
            Text(f"{symbol} {label}", style=style),
        ]
        if verbose > 0 and r.detail:
            row.append(Text(r.detail, style="dim white"))
        elif verbose > 0:
            row.append(Text(""))
        table.add_row(*row)

    console.print(table)


def print_protocols() -> None:
    """Print the list of configured protocols."""
    from .config import PROTOCOLS

    console = Console()
    table = Table(title="Available Protocols", box=None, show_header=True, padding=(0, 2))
    table.add_column("Protocol", style="bold", no_wrap=True)
    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("Auth Required", no_wrap=True)
    table.add_column("Description")

    for name, proto in PROTOCOLS.items():
        auth = "yes" if proto.requires_auth else "no"
        table.add_row(name, str(proto.port), auth, proto.description)

    console.print(table)