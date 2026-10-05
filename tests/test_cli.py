import tempfile
from pathlib import Path

import pytest

from scylla.cli import _parse_targets
from scylla.runner import _build_nxc_args
from scylla.models import Credential, Target


def test_single_host():
    assert [t.host for t in _parse_targets(["10.0.0.5"])] == ["10.0.0.5"]


def test_multi_targets():
    hosts = [t.host for t in _parse_targets(["10.0.0.5", "10.0.0.6"])]
    assert hosts == ["10.0.0.5", "10.0.0.6"]


def test_cidr_expansion_and_dedupe():
    hosts = [t.host for t in _parse_targets(["192.168.1.1/31", "192.168.1.1"])]
    assert hosts == ["192.168.1.0", "192.168.1.1"]


def test_hostname_not_expanded():
    assert [t.host for t in _parse_targets(["dc01.corp.local"])] == ["dc01.corp.local"]


def test_target_file():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("# comment\n10.0.0.5\n10.0.0.6\n")
        path = f.name
    hosts = [t.host for t in _parse_targets([path])]
    assert hosts == ["10.0.0.5", "10.0.0.6"]


def test_mixed_file_and_hosts():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("10.0.0.5\n")
        path = f.name
    hosts = [t.host for t in _parse_targets([path, "10.0.0.7", "10.0.0.5"])]
    assert hosts == ["10.0.0.5", "10.0.0.7"]


def test_cidr_cap():
    with pytest.raises(ValueError, match="expands to"):
        _parse_targets(["10.0.0.0/8"])


def test_local_auth_flag():
    cmd = _build_nxc_args(
        proto=type("P", (), {"name": "smb"})(),
        target=Target(host="10.0.0.5"),
        cred=Credential(username="admin", password="pass"),
        local_auth=True,
    )
    assert cmd == ["nxc", "smb", "10.0.0.5", "-u", "admin", "-p", "pass", "--local-auth"]


def test_no_local_auth_flag():
    cmd = _build_nxc_args(
        proto=type("P", (), {"name": "smb"})(),
        target=Target(host="10.0.0.5"),
        cred=None,
    )
    assert "--local-auth" not in cmd
