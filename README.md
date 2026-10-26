# VPN Gate Connect (Cross-Platform Rust + Flutter Edition)

Unified cross-platform **SoftEther VPN Gate** client engineered around a **100% pure-Rust core** (`rustls`, pure-Rust `AES-256/128/3DES` + `MODP-1024` IKEv1, zero OpenSSL build dependency) targeting **Linux, Windows 11, macOS, Android, and iOS**.

## Architecture

- **`crates/vpngate-core`** — Shared Rust networking & tunnel engine:
  - Multi-source censorship-resilient discovery (official API + HTML + 5 HTTPS mirrors + `sdise` candidate recovery + IP-pinned Cloudflare DoH `1.1.1.1:443`)
  - 1-RTT IKEv1 Aggressive Mode `PSK == "vpn"` `HASH_R` cryptographic pre-flight verifier
  - Built-in Linux pure-Rust IKEv1 Phase 1 + Quick Mode + kernel `XFRM` ESPinUDP (`UDP 4500`) daemon (`vpngate _ikev1`)
  - Desktop tunnel drivers (`Linux` built-in XFRM + `xl2tpd` & native `nftables` / `nmcli` / `openvpn`; `Windows 11` `RASMAN`/`rasdial` + `openvpn.exe`; `macOS` OpenVPN + `.mobileconfig`), Cloudflare DNS leak protection (`1.1.1.1`, `1.0.0.1`), and background auto-reconnect watchdog (`vpngate _monitor`)
- **`crates/vpngate-cli`** — Single-binary Desktop CLI & `[0-8]` Interactive Console (`vpngate` / `vpngate.exe`)
- **`crates/vpngate-bridge`** — `flutter_rust_bridge` FFI crate (`cdylib` + `staticlib`) for Mobile & Desktop UI
- **`vpngate-launcher.py` & `vpngate.desktop`** — Native dark GNOME GTK/VTE dynamic-resizing window launcher with live tunnel status HeaderBar & Egress IP copy button
- **`mobile/`** — Flutter Cross-Platform Mobile application (`Android` `VpnService` + `iOS` `NEPacketTunnelProvider`)

---

## Quick Desktop Installation

### Kali / Debian / Ubuntu / Fedora / Arch / macOS

```bash
sh ./install-vpngate.sh
```

Launch from terminal or GNOME Application Grid:

```bash
vpngate              # Interactive [0-8] Console Dashboard
vpngate -w           # Dedicated dark GNOME GTK/VTE dynamic window
vpngate countries    # Live country & protocol summary table
vpngate connect -c JP
vpngate status
vpngate disconnect
```

Uninstall cleanly with zero residues:

```bash
sh ./install-vpngate.sh --uninstall
```

### Windows 11

Double-click **`install-vpngate.cmd`** (auto-elevates via UAC) or run in Administrator PowerShell:

```powershell
.\install-vpngate.ps1
vpngate
```

---

## Building & Testing from Source

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p vpngate-cli
```
