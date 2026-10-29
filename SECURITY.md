# Security Policy

## Supported Versions

Security fixes are applied exclusively on the active **`main`** branch (Pure-Rust x86_64 Desktop Edition). The **`PY`** branch is an inactive, frozen historical reference and receives no updates.

| Branch / Version | Status | Supported |
| :--- | :--- | :--- |
| **`main`** (Rust Workspace `0.2.x`) | Active | Yes |
| **`PY`** (Legacy Python `v5.3`) | Inactive / Frozen Reference | No |

## Security Architecture Highlights

- **Memory-Safe TLS & Cryptography**: Uses pure-Rust `rustls` and pure-Rust `AES-256/128/3DES` + `HMAC-SHA1/MD5` + `MODP-1024` IKEv1 packet handling without linking C OpenSSL into the core binary.
- **Strict Cryptographic Pre-Flight**: Archive or mirror-sourced L2TP candidate IPs are treated as untrusted until live IKEv1 Aggressive Mode `HASH_R` (`PSK == "vpn"`) verification succeeds and tunnel data-plane egress is verified.
- **DNS & Route Leak Prevention**: Locks tunnel DNS (`/etc/resolv.conf` + `systemd-resolved` on Linux, interface DNS & `block-outside-dns` on Windows 11) and preserves loopback IPv6 while restoring host networking cleanly on `vpngate disconnect` or `Ctrl+C`.
- **Least-Privilege File Ownership & Permissions**: Ephemeral tunnel credentials and PID/state files under `/run/vpngate-l2tp` and `~/.cache/vpngate` use restricted permissions and are scrubbed on `vpngate disconnect` and `--uninstall`.

## Reporting a Vulnerability

Please **do not** post unpatched privilege-escalation, command-injection, or DNS/route-leak vulnerabilities in public issues with exploit details.

Instead, report security issues privately through **[GitHub Private Vulnerability Reporting](https://github.com/warmaster726/vpngate-connect/security/advisories/new)** on this repository (or open a minimal GitHub Issue requesting a private contact channel if advisories are disabled).
