# VPN Gate Connect

Cross-platform **SoftEther VPN Gate** client and profile toolkit engineered around a **100% pure-Rust networking & cryptography core** (`rustls`, pure-Rust `AES-256/128/3DES` + `MODP-1024` IKEv1, zero OpenSSL build dependency) targeting **Linux, Windows 11, and macOS** (plus `.mobileconfig` & `MobileCore3`-patched `.ovpn` profile generation for iOS, Android, and routers).

---

## Key Capabilities

- **Automatic Multi-Protocol Failover (`Auto: L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP`)**
  - **1-RTT Cryptographic Pre-Flight Verification**: Verifies SoftEther `IKEv1` Aggressive Mode `HASH_R` (`PSK == "vpn"`, zero `IKEv2`) in a single UDP round-trip before dialing, pruning dead or custom-PSK volunteer nodes automatically.
  - **Built-In Pure-Rust Linux IKEv1/XFRM Engine**: Negotiates IKEv1 Phase 1 + Quick Mode NAT-T (`UDP 4500` `ESPinUDP`) and programs Linux kernel `XFRM` Security Associations directly—no `strongswan` or `libreswan` daemon conflicts.
  - **Native Windows 11 & macOS Support**: Automates Windows 11 `RASMAN`/`IKEEXT` L2TP (`AssumeUDPEncapsulationContextOnSendRule = 2`) + headless Zero-Prompt OpenVPN Community (`OpenVPN.OpenVPN`), and generates Apple `.mobileconfig` + patched OpenVPN profiles (`OpenVpn26` & `MobileCore3`).
- **Multi-Layer Censorship & Firewall Resilience**
  - **Official VPN Gate Daily Mirror Sites (`sites.aspx`)**: Automatically harvests, caches (`mirrors_cache.json`), probes, and fails over to Official VPN Gate Mirror Portals (`http://<mirror>:<port>/en/` & `/api/iphone/`), including ASP.NET `C_L2TP=on` / `C_OpenVPN=on` protocol tables.
  - **HTTPS Mirror & Archive Recovery**: Enriches the relay pool from 5+ HTTPS GitHub/CDN CSV mirrors plus Internet Archive CDX & `funcra` history pools (admitting archive L2TP candidates *only* if live cryptographic `PSK == "vpn"` verification succeeds right now).
  - **IP-Pinned Cloudflare DoH (`1.1.1.1:443`)**: Bypasses ISP DNS poisoning and locks tunnel DNS (`1.1.1.1`, `1.0.0.1`) against leaks.
- **Interactive `[0-9]` Console + Native Dark GNOME GTK/VTE Window**
  - Screen-cleared step-by-step live execution progress with in-place spinners, dynamically resizing Unicode boxes/tables, 30-minute per-protocol dead-server cooldowns, and an optional 15-second background Auto-Reconnect Watchdog (`vpngate _monitor`).
  - On Linux/GNOME, includes `vpngate-launcher` (`GTK3/VTE-2.91` -> `GTK4/VTE-3.91`) with a dark CSD HeaderBar live tunnel status badge and one-click Egress IP copy chip.

---

## Repository Branches

| Branch | Description |
| :--- | :--- |
| **`main`** | **Active Pure-Rust Edition** (`vpngate-core`, `vpngate-cli`, Desktop installers & GNOME launcher) |
| **`PY`** | **Legacy Python `v5.3` Single-Script Edition** (preserved as a reference implementation) |

---

## Quick Installation

### Linux (Kali, Debian, Ubuntu, Mint, Pop!_OS, Fedora, Arch) & macOS

**One-liner install (once repository is public):**

```bash
curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh
```

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

### Windows 11

**One-liner install in Administrator PowerShell (once repository is public):**

```powershell
irm https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.ps1 | iex
```

**Or from a local `git clone`:**
- Double-click **`install-vpngate.cmd`** (auto-elevates via Windows UAC), or run `.\install-vpngate.ps1` in an elevated PowerShell window.
- Uninstall anytime with `.\install-vpngate.ps1 --uninstall`.

---

### Building Manually From Source (Rust / Cargo)

Because TLS (`rustls`) and IKEv1 cryptography are implemented in pure Rust and exact crate versions are pinned in [`Cargo.lock`](Cargo.lock), **no OpenSSL headers, `pkg-config`, or `cmake` are required**—only a standard Rust toolchain (`rustup`) and a basic C linker (`gcc`/`clang` on Unix, or MSVC / MinGW-w64 `gcc.exe` on Windows):

```bash
# Option A — Install directly from Git with Cargo (any OS with Rust installed):
cargo install --git https://github.com/warmaster726/vpngate-connect.git --locked vpngate-cli

# Option B — Clone & compile a standalone release binary manually:
git clone https://github.com/warmaster726/vpngate-connect.git
cd vpngate-connect
cargo build --release --locked -p vpngate-cli
# Output binary: ./target/release/vpngate  (Windows: .\target\release\vpngate.exe)
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
```

---

## Workspace Layout

```text
vpngate-connect/
├── crates/
│   ├── vpngate-core/      # Pure-Rust discovery, Official Mirrors, DoH, IKEv1/XFRM & profile generators
│   └── vpngate-cli/       # Single-binary `vpngate` CLI & [0-9] Interactive Console
├── vpngate-launcher.py    # GNOME GTK3/GTK4 + VTE dynamic-resizing dark window launcher
├── vpngate.desktop        # XDG Desktop Entry + GNOME Dash Quick Actions
├── install-vpngate.sh     # POSIX /bin/sh Linux & macOS installer, residue cleaner & uninstaller
├── install-vpngate.ps1    # Windows 11 PowerShell installer, NAT-T & Zero-Prompt OpenVPN configurator
└── install-vpngate.cmd    # Windows 11 UAC auto-elevating Batch wrapper
```

---

## Attribution & Academic Credit

This project is an independent open-source client designed to interoperate with public relay servers operated by volunteers of the **[VPN Gate Academic Experiment Project](https://www.vpngate.net/en/about_us.aspx)** at the **Graduate School of Systems and Information Engineering, University of Tsukuba, Japan**, built upon **[SoftEther VPN](https://www.softether.org/)** open-source software.

This repository is **not** affiliated with or endorsed by the University of Tsukuba or SoftEther Corporation.

---

## Acceptable Use, Anti-Abuse & Legal Disclaimer

1. **Compliance with Local Laws & VPN Gate Anti-Abuse Policy**: Users are solely responsible for ensuring that accessing VPN Gate mirror portals and connecting to public VPN Gate volunteer relays complies with applicable local laws, network policies, and the [VPN Gate Anti-Abuse Policy](https://www.vpngate.net/en/about_abuse.aspx).
2. **Volunteer Relay Logging Notice**: Per the VPN Gate Academic Experiment Project's anti-abuse architecture, volunteer VPN Gate relay servers maintain connection logs to prevent network abuse and cybercrime. Do **not** use public VPN Gate relays for unauthorized access, spam, copyright infringement, or unlawful activity.
3. **No Warranty**: Provided `"AS IS"` under the [MIT License](LICENSE), without warranty of any kind.
