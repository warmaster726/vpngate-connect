# VPN Gate Connect

Censorship-resilient **SoftEther VPN Gate** desktop client engineered around a **100% pure-Rust networking & cryptography core** (`rustls`, pure-Rust `AES-256/128/3DES` + `MODP-1024` IKEv1, zero OpenSSL build dependency) for **x86_64 Linux, Windows 11, and Intel macOS**.

**Architecture:** desktop is **x86_64-native only**. ARM64 (Apple Silicon, Windows-on-ARM, aarch64 Linux), 32-bit, Rosetta, and x64 emulation are not supported. The web client is unchanged.

---

## Key Capabilities

- **Automatic Multi-Protocol Failover (`Auto: L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP`)**
  - **1-RTT Cryptographic Pre-Flight Verification**: Verifies SoftEther `IKEv1` Aggressive Mode `HASH_R` (`PSK == "vpn"`, zero `IKEv2`) in a single UDP round-trip before dialing, pruning dead or custom-PSK volunteer nodes automatically.
  - **Built-In Pure-Rust Linux IKEv1/XFRM Engine**: Negotiates IKEv1 Phase 1 + Quick Mode NAT-T (`UDP 4500` `ESPinUDP`) and programs Linux kernel `XFRM` Security Associations directly—no `strongswan` or `libreswan` daemon conflicts.
  - **Native Windows 11 & macOS Support**: Automates Windows 11 `RASMAN`/`IKEEXT` L2TP (`AssumeUDPEncapsulationContextOnSendRule = 2`) + headless Zero-Prompt OpenVPN Community (`OpenVPN.OpenVPN`), and supports native macOS L2TP (`.mobileconfig`) + patched OpenVPN profiles.
- **Multi-Layer Censorship & Firewall Resilience**
  - **Official VPN Gate Daily Mirror Sites (`sites.aspx`)**: Automatically harvests, caches (`mirrors_cache.json`), probes, and fails over to Official VPN Gate Mirror Portals (`http://<mirror>:<port>/en/` & `/api/iphone/`), including ASP.NET `C_L2TP=on` / `C_OpenVPN=on` protocol tables.
  - **HTTPS Mirror & Archive Recovery**: Enriches the relay pool from 5+ HTTPS GitHub/CDN CSV mirrors plus Internet Archive CDX & `funcra` history pools (admitting archive L2TP candidates *only* if live cryptographic `PSK == "vpn"` verification succeeds right now) and backfills 100% inline `.ovpn` certificates.
  - **IP-Pinned Cloudflare DoH (`1.1.1.1:443`) & Leak Protection**: Bypasses ISP DNS poisoning, enforces tunnel DNS (`1.1.1.1`, `1.0.0.1`), and restores host routes, `/etc/resolv.conf` / `systemd-resolved`, and IPv6 state cleanly on teardown.
- **Interactive `[0-9]` Console + Native Dark GNOME GTK/VTE Window**
  - Screen-cleared step-by-step live execution progress with in-place spinners, dynamically resizing Unicode boxes/tables, 30-minute per-protocol dead-server cooldowns, and an optional 15-second background Auto-Reconnect Watchdog (`vpngate _monitor`).
  - On Linux/GNOME, includes `vpngate-launcher` (`GTK3/VTE-2.91` -> `GTK4/VTE-3.91`) with a dark CSD HeaderBar live tunnel status badge and one-click Egress IP copy chip.

---

## Repository Branches

| Branch | Status | Description |
| :--- | :--- | :--- |
| **`main`** | **Active (Default)** | **Pure-Rust x86_64 Desktop Edition** (`vpngate-core`, `vpngate-cli`, Linux/macOS & Windows 11 installers, GNOME GTK/VTE launcher) |
| **`PY`** | **Inactive (Archived Reference)** | Frozen legacy Python `v5.3` single-script edition preserved read-only for historical reference (no further updates) |

---

## Quick Installation

### Linux (Kali, Debian, Ubuntu, Mint, Pop!_OS, Fedora, Arch) & macOS — x86_64 only

**One-liner install:**

```bash
curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh
```

If a Rust toolchain or C linker must be downloaded to compile from source, the installer **asks whether to keep those compile tools** or **remove them after `vpngate` is built**. Pre-existing toolchains are left untouched. Non-interactive runs remove tools this installer added; pass `--keep-toolchain` or `--remove-toolchain` to skip the prompt.

**Or from a local `git clone`:**

```bash
git clone https://github.com/warmaster726/vpngate-connect.git
cd vpngate-connect
sh ./install-vpngate.sh
```

**Uninstall cleanly with zero remaining residues:**

```bash
sh ./install-vpngate.sh --uninstall
```

---

### Windows 11 — x86_64 (amd64) only

**One-liner install in Administrator PowerShell:**

```powershell
irm https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.ps1 | iex
```

Same compile-tool prompt as Linux: keep or remove Rust / MinGW after `vpngate.exe` is built (`-KeepToolchain` / `-RemoveToolchain`).

**Or from a local `git clone`:**
- Double-click **`install-vpngate.cmd`** (auto-elevates via Windows UAC), or run `.\install-vpngate.ps1` in an elevated PowerShell window.
- Uninstall anytime with `.\install-vpngate.ps1 --uninstall`.

---

### Building Manually From Source (Rust / Cargo)

Because TLS (`rustls`) and IKEv1 cryptography are implemented in pure Rust and exact crate versions are pinned in [`Cargo.lock`](Cargo.lock), **no OpenSSL headers, `pkg-config`, or `cmake` are required**—only a standard Rust toolchain (`rustup`) and a basic C linker (`gcc`/`clang` on Unix, or MSVC / MinGW-w64 `gcc.exe` on Windows):

```bash
# Option A — Install directly from Git with Cargo (x86_64 host with Rust installed):
cargo install --git https://github.com/warmaster726/vpngate-connect.git --locked vpngate-cli --target x86_64-unknown-linux-gnu
# Windows:  --target x86_64-pc-windows-msvc   (or x86_64-pc-windows-gnu)
# macOS:    --target x86_64-apple-darwin

# Option B — Clone & compile a standalone x86_64 release binary:
git clone https://github.com/warmaster726/vpngate-connect.git
cd vpngate-connect
cargo build --release --locked -p vpngate-cli --target x86_64-unknown-linux-gnu
# Linux:  ./target/x86_64-unknown-linux-gnu/release/vpngate
# Windows MSVC: cargo build --release --locked -p vpngate-cli --target x86_64-pc-windows-msvc
#               .\target\x86_64-pc-windows-msvc\release\vpngate.exe
# macOS:  cargo build --release --locked -p vpngate-cli --target x86_64-apple-darwin
```

---

## Usage (`vpngate`)

```bash
vpngate                        # Launch Interactive Console Dashboard [0-9]
vpngate -w                     # Launch inside dedicated dark GNOME GTK/VTE or Windows Terminal window
vpngate countries              # View unified countries & protocol summary table
vpngate list -c JP -n 15       # List top 15 servers in Japan
vpngate connect -c JP          # Auto-connect to Japan (L2TP/IPsec -> OVPN UDP -> OVPN TCP)
vpngate connect -c KR -p l2tp  # Connect using verified PSK='vpn' L2TP/IPsec only
vpngate mirrors                # Discover & live-probe Official VPNGate Mirror Sites
vpngate --mirror http://host:port/en/ refresh
vpngate status                 # Check live tunnel, kernel XFRM SA, watchdog & Cloudflare egress IP
vpngate watchdog on            # Arm 15s background Auto-Reconnect Watchdog
vpngate doctor                 # Run IKEv1 crypto, L2TP/XFRM, OpenVPN & gateway diagnostics
vpngate disconnect             # Tear down active VPN and restore host routes, DNS & firewall
vpngate update                 # Scan public main for a newer desktop (no GitHub login) and replace this install
vpngate upgrade                # Same as `vpngate update`
```

The interactive `[0-9]` dashboard also scans for a newer desktop over anonymous HTTPS (`raw.githubusercontent.com` and jsDelivr — no GitHub account or 2FA). The dashboard shows whether you are up to date, a newer version is available, or the check failed. If a newer version is found you are encouraged to install it; confirming runs the public installer, which disconnects any tunnel, deletes the previous `vpngate` binary, and installs the new one. Use `--no-update-check` to skip the dashboard scan, or `vpngate update -y` to install without a second prompt. Pool refresh stays `vpngate refresh`.

---

## Workspace Layout

```text
vpngate-connect/
├── crates/
│   ├── vpngate-core/      # Pure-Rust discovery, Official Mirrors, DoH, IKEv1/XFRM & desktop tunnel engine
│   └── vpngate-cli/       # Single-binary `vpngate` CLI & [0-9] Interactive Console
├── vpngate-launcher.py    # GNOME GTK3/GTK4 + VTE dynamic-resizing dark window launcher
├── assets/                # Desktop app icon (gate mark, no VG glyph) — SVG / PNG / Windows ICO
├── vpngate.desktop        # XDG Desktop Entry + GNOME Dash Quick Actions
├── install-vpngate.sh     # POSIX /bin/sh Linux & macOS installer, residue cleaner & uninstaller
├── install-vpngate.ps1    # Windows 11 PowerShell installer, NAT-T & Zero-Prompt OpenVPN configurator
├── install-vpngate.cmd    # Windows 11 UAC auto-elevating Batch wrapper
└── web/                   # Isolated Cloudflare Workers Web Profile Portal (.mobileconfig & .ovpn export)
```

> **Isolation Note:** `web/` is a standalone zero-dependency Cloudflare Worker (`wrangler.toml` + `src/worker.js`) for browser-based iOS/Android `.mobileconfig` and `.ovpn` profile provisioning. Desktop installers (`install-vpngate.sh`, `install-vpngate.ps1`, `install-vpngate.cmd`) compile strictly `-p vpngate-cli` inside a temporary build root and never build, run, or copy `web/`.

---

## Attribution & Academic Credit

This project is an independent open-source client designed to interoperate with public relay servers operated by volunteers of the **[VPN Gate Academic Experiment Project](https://www.vpngate.net/en/about_us.aspx)** at the **Graduate School of Systems and Information Engineering, University of Tsukuba, Japan**, built upon **[SoftEther VPN](https://www.softether.org/)** open-source software.

This repository is **not** affiliated with or endorsed by the University of Tsukuba or SoftEther Corporation.

---

## Acceptable Use, Anti-Abuse & Legal Disclaimer

1. **Compliance with Local Laws & VPN Gate Anti-Abuse Policy**: Users are solely responsible for ensuring that accessing VPN Gate mirror portals and connecting to public VPN Gate volunteer relays complies with applicable local laws, network policies, and the [VPN Gate Anti-Abuse Policy](https://www.vpngate.net/en/about_abuse.aspx).
2. **Volunteer Relay Logging Notice**: Per the VPN Gate Academic Experiment Project's anti-abuse architecture, volunteer VPN Gate relay servers maintain connection logs to prevent network abuse and cybercrime. Do **not** use public VPN Gate relays for unauthorized access, spam, copyright infringement, or unlawful activity.
3. **No Warranty**: Provided `"AS IS"` under the [MIT License](LICENSE), without warranty of any kind.
