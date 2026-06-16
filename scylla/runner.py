import asyncio
import re
from typing import Optional

from .config import PROTOCOLS, DEFAULT_TIMEOUT, Protocol
from .models import Credential, ProtocolStatus, SweepResult, Target


def _build_nxc_args(
    proto: Protocol,
    target: Target,
    cred: Optional[Credential],
) -> list[str]:
    cmd = ["nxc", proto.name, target.host]
    if cred:
        cmd.extend(["-u", cred.username])
        if cred.ntlm_hash:
            cmd.extend(["-H", cred.ntlm_hash])
        elif cred.password:
            cmd.extend(["-p", cred.password])
    return cmd


def _infer_status(output: str) -> tuple[ProtocolStatus, str]:
    """Parse nxc's stderr output to determine protocol status.

    nxc writes everything to stderr using markers:
      [*] banner / info
      [+] success / authenticated
      [-] failure / access denied / login failed
    """
    lower = output.lower()

    # Error conditions
    if "module '" in lower and "' not found" in lower:
        return ProtocolStatus.ERROR, "Protocol unavailable"
    if "is not a valid protocol" in lower:
        return ProtocolStatus.ERROR, "Protocol unavailable"
    if "connection refused" in lower:
        return ProtocolStatus.CLOSED, "Connection refused"
    if "timed out" in lower:
        return ProtocolStatus.CLOSED, "Timed out"
    if "could not connect" in lower:
        return ProtocolStatus.CLOSED, "Could not connect"
    if "name or service not known" in lower:
        return ProtocolStatus.ERROR, "Unknown host"
    if "no route to host" in lower:
        return ProtocolStatus.CLOSED, "No route to host"
    if "requires" in lower and "argument" in lower:
        return ProtocolStatus.ERROR, "Missing required argument"

    # Look for [+] success markers (auth success, share listing, etc.)
    if re.search(r'\[\+\]', output):
        detail = ""
        # Extract useful detail from [+] lines
        for line in output.splitlines():
            if "[+]" in line:
                detail = line.split("[+]", 1)[1].strip()
                break
        if "Pwn3d!" in output:
            detail = "Admin (Pwn3d!)"
        return ProtocolStatus.AUTHENTICATED, detail

    # Look for [-] failure markers with creds (wrong password, access denied)
    if re.search(r'\[\-\]', output):
        detail = ""
        for line in output.splitlines():
            if "[-]" in line:
                detail = line.split("[-]", 1)[1].strip()
                break
        if "access denied" in lower:
            return ProtocolStatus.ERROR, "Access denied"
        if "logon failure" in lower or "login failure" in lower:
            return ProtocolStatus.ERROR, "Login failed"
        return ProtocolStatus.ERROR, detail or "Failed"

    # Look for [*] marker — means the protocol responded (banner info)
    if re.search(r'\[\*\]', output):
        detail = ""
        for line in output.splitlines():
            if "[*]" in line:
                detail = line.split("[*]", 1)[1].strip()
                break
        return ProtocolStatus.OPEN, detail or "Listening"

    # If we got any output at all, the host is probably reachable
    if output.strip():
        return ProtocolStatus.OPEN, "Responded"
    return ProtocolStatus.CLOSED, "No response"


async def _run_single(
    proto: Protocol,
    target: Target,
    cred: Optional[Credential],
    timeout: int,
) -> SweepResult:
    cmd = _build_nxc_args(proto, target, cred)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        # nxc outputs everything to stderr, stdout is almost always empty
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        output = stderr + stdout
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except (ProcessLookupError, UnboundLocalError):
            pass
        return SweepResult(
            target=target,
            credential=cred,
            protocol=proto.name,
            status=ProtocolStatus.TIMEOUT,
            detail=f"Timed out after {timeout}s",
        )
    except FileNotFoundError:
        return SweepResult(
            target=target,
            credential=cred,
            protocol=proto.name,
            status=ProtocolStatus.ERROR,
            detail="nxc not found on PATH",
        )

    status, detail = _infer_status(output)
    return SweepResult(
        target=target,
        credential=cred,
        protocol=proto.name,
        status=status,
        detail=detail,
        raw_output=output.strip(),
    )


def _should_skip(proto: Protocol, cred: Optional[Credential]) -> bool:
    if not proto.requires_auth:
        return False
    return not cred or not cred.has_auth


async def sweep(
    targets: list[Target],
    credentials: list[Optional[Credential]],
    protocols: list[Protocol],
    timeout: int = DEFAULT_TIMEOUT,
    max_parallel: int = 0,
) -> list[SweepResult]:
    results: list[SweepResult] = []
    semaphore = asyncio.Semaphore(max_parallel) if max_parallel > 0 else None

    async def _run_one(proto: Protocol, target: Target, cred: Optional[Credential]) -> SweepResult:
        if _should_skip(proto, cred):
            return SweepResult(
                target=target,
                credential=cred,
                protocol=proto.name,
                status=ProtocolStatus.SKIPPED,
                detail="Credentials required",
            )
        if semaphore:
            async with semaphore:
                return await _run_single(proto, target, cred, timeout)
        return await _run_single(proto, target, cred, timeout)

    tasks = []
    for target in targets:
        creds = credentials if credentials else [None]
        for cred in creds:
            for proto in protocols:
                tasks.append(_run_one(proto, target, cred))

    results = await asyncio.gather(*tasks)
    return results