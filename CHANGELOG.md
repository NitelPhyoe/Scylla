# Changelog

## 0.2.0 — 2026-10-05

- Added `--local-auth` flag to authenticate as a local user (passed through to nxc).
- Multi-target support: `scylla 10.0.0.5 10.0.0.6 192.168.1.0/24 targets.txt`.
- CIDR ranges are expanded per-host for real per-host status (deduped across targets, capped at 4096 hosts per network).
- Target files can now be mixed freely with inline hosts; `#` comments supported.
- Fixed version lookup after package rename to `scylla`.

## 0.1.1 — 2026-06-16

- Version display in CLI help for clarity.
- Verbose output (`-vv`) shows raw nxc output details.
- README improvements.

## 0.1.0 — 2026-06-16

- Initial release: multi-protocol credential sweep via nxc, credential files, protocol selection, parallel execution, JSON/verbose output.
