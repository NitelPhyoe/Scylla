# Scylla

Multi-protocol credential sweep tool for [NetExec](https://github.com/Pennyw0rth/NetExec) (nxc).

During CTFs and pentests, you find a credential set — maybe from a hash dump, maybe from an AS-REP roast, maybe from a bloodhound path. Then comes the boring part: running `nxc smb`, `nxc winrm`, `nxc mssql`, `nxc ldap` one by one, typing the same credentials over and over, watching each spin up separately. Lost time. Repetitive. Made no sense.

So I built Scylla. One command, all protocols, parallel. By [Phyo Zin Khant](https://www.phyozinkhant.dev).

---

Scylla is a minimal, modern CLI tool that sweeps credentials across every protocol nxc supports. It runs protocols in parallel, color-codes results by status (green ✓ authenticated, yellow ● listening, red ✗ closed), and gives you a clean summary — no noise, no redundant typing.

## Install

```bash
pipx install git+https://github.com/NitelPhyoe/Scylla.git
```

Requires `netexec` (nxc) to be installed and available on PATH.

## Usage

```bash
# Single target with credentials
scylla sweep 10.0.0.5 -u admin -p Password123

# Only specific protocols
scylla sweep 10.0.0.5 -u admin -p Password123 --protocols smb,winrm,rdp

# Multiple targets from file, multiple creds
scylla sweep targets.txt -c creds.txt

# NTLM hash auth
scylla sweep 10.0.0.5 -u admin -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# No credentials (null/anonymous probe)
scylla sweep 10.0.0.5

# Verbose output
scylla sweep 10.0.0.5 -u admin -p Password123 -v

# JSON output for automation
scylla sweep 10.0.0.5 -u admin -p Password123 --json

# List available protocols
scylla protocols
```
