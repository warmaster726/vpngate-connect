# Security Policy

## Supported Versions

Security fixes are applied on the active **`main`** branch (Pure-Rust Cross-Platform Edition). The **`PY`** branch is preserved for historical reference only.

| Branch / Version | Supported |
| :--- | :--- |
| `main` (Rust Workspace `0.1.x`) | Yes |
| `PY` (Legacy Python `v5.3`) | Reference only |

## Security Architecture Highlights

- **Memory-Safe TLS & Cryptography**: Uses pure-Rust `rustls` and pure-Rust `AES-256/128/3DES` + `HMAC-SHA1/MD5` + `MODP-1024` IKEv1 packet handling without linking C OpenSSL into the core binary.
- **Strict Cryptographic Pre-Flight**: Archive or mirror-sourced L2TP candidate IPs are treated as untrusted until live IKEv1 Aggressive Mode `HASH_R` verification succeeds and tunnel data-plane egress is verified.
- **Least-Privilege File Ownership & Permissions**: Ephemeral tunnel credentials and PID/state files under `/run/vpngate-l2tp` and `~/.cache/vpngate` use restricted permissions and are scrubbed on `vpngate disconnect` and `--uninstall`.

## Reporting a Vulnerability

Please **do not** post unpatched privilege-escalation, command-injection, or DNS/route-leak vulnerabilities in public issues with exploit details.

Instead, report security issues privately through **[GitHub Private Vulnerability Reporting](https://github.com/warmaster726/vpngate-connect/security/advisories/new)** on this repository (or open a minimal GitHub Issue requesting a private contact channel if advisories are disabled).
