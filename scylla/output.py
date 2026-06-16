import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .config import PROTOCOL_COLORS
from .models import ProtocolStatus, SweepResult


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

_SHOWN_STATUSES = {
    ProtocolStatus.AUTHENTICATED,
    ProtocolStatus.OPEN,
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

    if verbose > 0:
        t.append("\n")
        t.append("  ", style="dim")
        if result.detail:
            t.append(f"└─ {result.detail}", style="dim white")
        else:
            t.append("└─ No additional detail", style="dim white")

    if verbose > 1 and result.raw_output:
        lines = result.raw_output.splitlines()
        for line in lines[:20]:
            t.append("\n")
            t.append("  │ ", style="dim")
            t.append(line.strip(), style="dim cyan")

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

    visible = [r for r in results if r.status in _SHOWN_STATUSES]

    for r in visible:
        console.print(format_result(r, verbose=verbose))

    success_count = sum(1 for r in results if r.success)
    total = len(results)
    console.print()
    if success_count == 0:
        text = Text(f"  {success_count}/{total} protocols accessible", style="bold red")
    elif success_count == total:
        text = Text(f"  {success_count}/{total} all open! ", style="bold green")
    else:
        text = Text(f"  {success_count}/{total} protocols accessible", style="bold yellow")
    console.print(text)


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