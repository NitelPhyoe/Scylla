import asyncio
import json
import shlex
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
    cmd.extend(["--json"])
    return cmd


def _infer_status(stderr: str, stdout: str) -> tuple[ProtocolStatus, str]:
    lower_stderr = stderr.lower()
    lower_stdout = stdout.lower()

    if "access denied" in lower_stderr:
        return ProtocolStatus.ERROR, "Access denied"
    if "connection refused" in lower_stderr or "connection refused" in lower_stdout:
        return ProtocolStatus.CLOSED, "Connection refused"
    if "connection timed out" in lower_stderr or "name or service not known" in lower_stderr:
        return ProtocolStatus.ERROR, "Connection timeout"
    if "timed out" in lower_stderr:
        return ProtocolStatus.CLOSED, "Timed out"
    if "module not found" in lower_stderr or "is not a valid protocol" in lower_stderr:
        return ProtocolStatus.ERROR, "Protocol unavailable"
    if "could not connect" in lower_stderr:
        return ProtocolStatus.CLOSED, "Could not connect"
    if "requires" in lower_stderr and "argument" in lower_stderr:
        return ProtocolStatus.ERROR, "Missing required argument"

    try:
        if stdout.strip():
            lines = stdout.strip().splitlines()
            for line in lines:
                data = json.loads(line)
                if (
                    data.get("logged_in") is True
                    or data.get("authenticated") is True
                ):
                    detail = data.get("detail", "")
                    if "Pwn3d!" in stdout:
                        detail = "Admin (Pwn3d!)"
                    return ProtocolStatus.AUTHENTICATED, detail
    except (json.JSONDecodeError, KeyError):
        pass

    if stdout.strip():
        return ProtocolStatus.OPEN, "Listening"
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
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        if hasattr(proc, "kill"):
            try:
                proc.kill()
            except ProcessLookupError:
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

    status, detail = _infer_status(stderr, stdout)
    return SweepResult(
        target=target,
        credential=cred,
        protocol=proto.name,
        status=status,
        detail=detail,
        raw_output=stdout.strip() + stderr.strip(),
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