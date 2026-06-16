"""
Scylla — Multi-protocol credential sweep tool for NetExec (nxc).

Usage:
    scylla sweep <target> [options]
    scylla protocols
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from .config import DEFAULT_TIMEOUT, resolve_protocols
from .models import Credential, Target
from .output import print_protocols, print_results
from .runner import sweep


def _parse_creds_file(path: str) -> list[Credential]:
    creds: list[Credential] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                creds.append(Credential.from_line(line))
    return creds


def _parse_targets(source: str) -> list[Target]:
    path = Path(source)
    if path.exists():
        targets: list[Target] = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(Target(host=line))
        return targets
    return [Target(host=source)]


def _build_credentials(args: argparse.Namespace) -> list[Optional[Credential]]:
    results: list[Optional[Credential]] = []
    if args.creds_file:
        results.extend(_parse_creds_file(args.creds_file))
    else:
        cred = None
        if args.username:
            cred = Credential(
                username=args.username,
                password=args.password,
                ntlm_hash=args.hash,
            )
        results.append(cred)
    return results


def cmd_protocols(args: argparse.Namespace) -> None:
    print_protocols()


def cmd_sweep(args: argparse.Namespace) -> None:
    targets = _parse_targets(args.target)
    credentials = _build_credentials(args)
    try:
        protocols = resolve_protocols(args.protocols)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    timeout = args.timeout
    max_parallel = args.parallel
    verbose = args.verbose
    output_json = args.json

    if len(protocols) == 0:
        print("No protocols to sweep (use --protocols to specify, or check config)", file=sys.stderr)
        sys.exit(1)

    results = asyncio.run(
        sweep(
            targets=targets,
            credentials=credentials,
            protocols=protocols,
            timeout=timeout,
            max_parallel=max_parallel,
        )
    )

    print_results(results, verbose=verbose, output_json=output_json)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="scylla",
        description="Multi-protocol credential sweep tool for NetExec (nxc).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  scylla sweep 10.0.0.5 -u admin -p Password123\n"
            "  scylla sweep 10.0.0.5 -u admin -H <ntlm_hash>\n"
            "  scylla sweep targets.txt -c creds.txt --protocols smb,winrm\n"
            "  scylla sweep 10.0.0.5\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scylla protocols
    p_protocols = subparsers.add_parser("protocols", help="List available protocols")

    # scylla sweep
    p_sweep = subparsers.add_parser("sweep", help="Sweep protocols on a target")
    p_sweep.add_argument("target", help="Target IP, CIDR range, or path to target file")
    p_sweep.add_argument("-u", "--username", help="Username for authentication")
    p_sweep.add_argument("-p", "--password", help="Password for authentication")
    p_sweep.add_argument("-H", "--hash", help="NTLM hash for authentication (LM:NT)")
    p_sweep.add_argument(
        "-c", "--creds-file",
        help="Path to credentials file (user:pass per line)",
    )
    p_sweep.add_argument(
        "--protocols",
        help="Comma-separated protocol list (default: all)",
    )
    p_sweep.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout per protocol in seconds (default: {DEFAULT_TIMEOUT})",
    )
    p_sweep.add_argument(
        "--parallel",
        type=int,
        default=0,
        help="Max parallel protocols (default: unlimited)",
    )
    p_sweep.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv)",
    )
    p_sweep.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()
    if args.command == "protocols":
        cmd_protocols(args)
    elif args.command == "sweep":
        # Parse comma-separated protocols
        if args.protocols:
            args.protocols = [p.strip() for p in args.protocols.split(",")]
        cmd_sweep(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()