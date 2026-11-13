# VPN Gate Connect

Censorship-resilient **SoftEther VPN Gate** desktop client engineered around a **100% pure-Rust networking & cryptography core** (`rustls`, pure-Rust `AES-256/128/3DES` + `MODP-1024` IKEv1, zero OpenSSL build dependency) for **64-bit Linux, Windows 11, and macOS** (`x86_64` and `aarch64`).

**Architecture:** desktop is **64-bit native** — `x86_64` and ARM64 (Apple Silicon, Windows-on-ARM, aarch64 Linux). 32-bit, Rosetta, and Windows-on-ARM x64 emulation are not supported. The web client is unchanged.

---

## Key Capabilities

- **Automatic Multi-Protocol Failover (`Auto: L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP`)**
  - **1-RTT Cryptographic Pre-Flight Verification**: Verifies SoftEther `IKEv1` Aggressive Mode `HASH_R` (`PSK == "vpn"`, zero `IKEv2`) in a single UDP round-trip before dialing, pruning dead or custom-PSK volunteer nodes automatically.
  - **Built-In Pure-Rust Linux IKEv1/XFRM Engine**: Negotiates IKEv1 Phase 1 + Quick Mode NAT-T (`UDP 4500` `ESPinUDP`) and programs Linux kernel `XFRM` Security Associations directly—no `strongswan` or `libreswan` daemon conflicts.
  - **Native Windows 11 & macOS Support**: Automates Windows 11 `RASMAN`/`IKEEXT` L2TP (`AssumeUDPEncapsulationContextOnSendRule = 2`) + headless Zero-Prompt OpenVPN Community (`OpenVPN.OpenVPN`), and supports native macOS L2TP (`.mobileconfig`) + patched OpenVPN profiles.
- **Multi-Layer Censorship & Firewall Resilience**
  - **Official VPN Gate Daily Mirror Sites (`sites.aspx`)**: Automatically harvests, caches (`mirrors_cache.json`), probes, and fails over to Official VPN Gate Mirror Portals (`http://<mirror>:<port>/en/` & `/api/iphone/`), including ASP.NET `C_L2TP=on` / `C_OpenVPN=on` protocol tables.
  - **HTTPS Mirror & Archive Recovery**: Enriches the relay pool from 5+ HTTPS GitHub/CDN CSV mirrors plus Internet Archive CDX & `funcra` history pools (admitting archive L2TP candidates *only* if live cryptographic `PSK == "vpn"` verification succeeds right now) and backfills 100% inline `.ovpn` certificates.
  - **IP-Pinned Cloudflare DoH (`1.1.1.1:443`) & Leak Protection**: Bypasses ISP DNS poisoning, uses tunnel DNS from the connection plus Cloudflare (`1.1.1.1`, `1.0.0.1`) and Google (`8.8.8.8`, `8.8.4.4`) including their IPv6 counterparts, and restores host routes, `/etc/resolv.conf` / `systemd-resolved`, and IPv6 state cleanly on teardown.
- **Native GUI with a retained CLI action service**
  - `vpngate-gui` is the desktop application for Linux, Windows 11, and macOS. It provides practical Connect, Relays, More actions, and System pages, light/dark themes, searchable multi-region selection, and in-layout operation progress bars.
  - `vpngate` remains installed as a command service for the GUI and for scripted CLI use. It no longer launches an interactive terminal dashboard or GTK/VTE/terminal window.
  - The GUI uses a per-user OS-backed singleton lock; a second GUI launch receives a clear notice. CLI worker commands do not acquire the GUI lock. GUI cancellation keeps the tunnel rollback behavior; the old shared-control/observer integration is removed.

---

## Repository Branches

| Branch | Status | Description |
| :--- | :--- | :--- |
| **`main`** | **Active (Default)** | Public **0.4.x** Pure-Rust 64-bit Desktop Edition; it remains unchanged until an authorized merge from `develop`. |
| **`develop`** | **Active (integration)** | Desktop **0.5.2**: native GUI operation-progress cards/bars and removal of the attempt-time setting from the GUI. The 0.5.1 searchable multi-region selection remains. Push integration work here first. |

---

## Quick Installation

### Linux (Kali, Debian, Ubuntu, Mint, Pop!_OS, Fedora, Arch) & macOS — 64-bit (`x86_64` and ARM64)

**One-liner install:**

```bash
curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh
```

If a Rust toolchain or C linker must be bootstrapped to compile from source, the installer **asks whether to keep those compile tools** or **remove them after the CLI command service and native GUI are built**. Pre-existing toolchains are left untouched. Non-interactive runs remove tools this installer added; pass `--keep-toolchain` or `--remove-toolchain` to skip the prompt.

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

### Windows 11 — 64-bit (`x86_64` and ARM64)

**One-liner install in Administrator PowerShell:**

```powershell
irm https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.ps1 | iex
```

Same compile-tool prompt as Linux: keep or remove Rust / MinGW after the CLI service and native GUI binaries are built (`-KeepToolchain` / `-RemoveToolchain`). The Start Menu contains one **VPN Gate Connect** GUI shortcut; `vpngate` remains available in PATH as the command service.

**Or from a local `git clone`:**
- Double-click **`install-vpngate.cmd`** (auto-elevates via Windows UAC), or run `.\install-vpngate.ps1` in an elevated PowerShell window.
- Uninstall anytime with `.\install-vpngate.ps1 --uninstall`.

---

### Building Manually From Source (Rust / Cargo)

The CLI action service uses pure-Rust TLS (`rustls`) and IKEv1 cryptography; it needs no OpenSSL headers. The native GUI is a separate eframe/egui Cargo workspace with its own lockfile. On Linux, building the GUI requires native X11/Wayland and fontconfig development libraries; the Linux installer installs the needed headers without GTK/VTE. A standard Rust toolchain and C linker are required for source builds.

```bash
# Option A — Install directly from Git with Cargo (64-bit host with Rust installed):
cargo install --git https://github.com/warmaster726/vpngate-connect.git --locked vpngate-cli --target x86_64-unknown-linux-gnu
# Linux ARM64:   --target aarch64-unknown-linux-gnu
# Windows x64:   --target x86_64-pc-windows-msvc   (or x86_64-pc-windows-gnu)
# Windows ARM64: --target aarch64-pc-windows-msvc
# macOS Intel:   --target x86_64-apple-darwin
# macOS Apple Silicon: --target aarch64-apple-darwin

# Option B — Clone & compile a standalone 64-bit release binary:
git clone https://github.com/warmaster726/vpngate-connect.git
cd vpngate-connect
cargo build --release --locked -p vpngate-cli --target x86_64-unknown-linux-gnu
# Linux x64:     ./target/x86_64-unknown-linux-gnu/release/vpngate
# Linux ARM64:   ./target/aarch64-unknown-linux-gnu/release/vpngate
# Windows x64:   .\target\x86_64-pc-windows-msvc\release\vpngate.exe
# Windows ARM64: .\target\aarch64-pc-windows-msvc\release\vpngate.exe
# macOS:         cargo build --release --locked -p vpngate-cli --target aarch64-apple-darwin   # or x86_64-apple-darwin
```

---

## Native GUI and CLI Command Service

Desktop 0.5.2 makes the native GUI the only interactive desktop frontend. It retains the 0.5.1 searchable multi-region selector and responsive Connect layout, and adds operation-progress cards/bars in the available page layout. The attempt-time threshold is no longer exposed as a GUI control.

- **VPN Gate Connect GUI** — run `vpngate-gui` for the eframe/egui interface on Linux, Windows 11, or macOS. It supports light/dark themes, connect, relay browsing, tools, status, diagnostics, watchdog, disconnect, and desktop update actions.
- **CLI action service** — run `vpngate --help` for the retained command/subcommand and operational flag reference. With no command, `vpngate` prints help; it does not open a terminal dashboard, GTK/VTE host, or Windows Terminal window.

Only the GUI uses the per-user OS-backed singleton lock. GUI command actions run through the companion `vpngate` binary, and short-lived service commands remain available while the GUI is open. Connect cancellation is operation-specific and retains rollback: cancelling a connection returns after VPN Gate tunnel/profile changes are rolled back or left unchanged.

The GUI checks for desktop updates anonymously at startup and after diagnostics; a newer version prompts with a strong recommendation to install. Privileged actions use Windows UAC, macOS authorization, or Linux `pkexec` where available. If a Linux system has no polkit agent, run a privileged CLI command from a terminal with `sudo` when required (for example, `sudo vpngate connect -c JP`).

The standard Linux/macOS and Windows installers build and install both the CLI service and native GUI. Linux installs the native GUI desktop entry; Windows creates one **VPN Gate Connect** GUI Start Menu shortcut. No GTK/VTE launcher is built or installed; the `vpngate` command remains available for CLI operations.

Build manually from a local clone:

```bash
cargo build --release --locked -p vpngate-cli
# Native GUI (separate Cargo workspace and Cargo.lock):
cargo build --release --locked --manifest-path crates/vpngate-gui/Cargo.toml --bin vpngate-gui
```

Run `vpngate-gui` to open the desktop app. For a direct GUI build, the executable is under `crates/vpngate-gui/target/release/` unless `CARGO_TARGET_DIR` is set.

---

## Usage (`vpngate`)

```bash
vpngate --help                 # Show the CLI command-service reference
vpngate                        # With no command, print help; no terminal dashboard is launched
vpngate-gui                    # Open the native VPN Gate Connect desktop GUI
vpngate countries              # View unified countries & protocol summary table
vpngate list -c JP -n 15       # List top 15 servers in Japan
vpngate connect -c JP          # Auto-connect to Japan (L2TP/IPsec -> OVPN UDP -> OVPN TCP)
vpngate connect -c JP,KR       # Japan and Korea, one sorted walk (repeat -c JP -c KR)
vpngate connect -c KR -p l2tp  # Connect using verified PSK='vpn' L2TP/IPsec only
vpngate mirrors                # Discover & live-probe Official VPNGate Mirror Sites
vpngate --mirror http://host:port/en/ refresh
vpngate cooldowns reset        # Clear failed-relay penalties without refreshing the pool
vpngate status                 # Check live tunnel, kernel XFRM SA, watchdog & Cloudflare egress IP
vpngate watchdog on            # Arm 15s background Auto-Reconnect Watchdog
vpngate doctor                 # Run IKEv1 crypto, L2TP/XFRM, OpenVPN & gateway diagnostics
vpngate disconnect             # Tear down active VPN and restore host routes, DNS & firewall
vpngate update                 # Scan public main for a newer desktop (no GitHub login) and replace this install
vpngate upgrade                # Same as `vpngate update`
```

The GUI checks for a newer desktop at **startup** and after diagnostics. Direct CLI `doctor` commands also check when run interactively unless `--no-update-check` is supplied. Checks use anonymous HTTPS (no GitHub account or 2FA). **GitHub raw `main` is authoritative**; jsDelivr is only a fallback if GitHub is unreachable. If a newer public version is found, the GUI or interactive CLI doctor prompts and strongly recommends installation; the public installer replaces the installed desktop binaries. Use `vpngate update -y` to install without a second prompt. Pool refresh stays `vpngate refresh`.

---

## Workspace Layout

```text
vpngate-connect/
├── crates/
│   ├── vpngate-core/      # Pure-Rust discovery, Official Mirrors, DoH, IKEv1/XFRM & desktop tunnel engine
│   ├── vpngate-cli/       # `vpngate` CLI command service for GUI and scripted use
│   └── vpngate-gui/       # Native eframe/egui GUI (`vpngate-gui`, separate Cargo workspace)
├── assets/                # Desktop app icon (gate mark, no VG glyph) — SVG / PNG / Windows ICO
├── vpngate-gui.desktop    # Native VPN Gate Connect desktop entry
├── install-vpngate.sh     # POSIX /bin/sh Linux & macOS installer, residue cleaner & uninstaller
├── install-vpngate.ps1    # Windows 11 PowerShell installer, NAT-T & Zero-Prompt OpenVPN configurator
├── install-vpngate.cmd    # Windows 11 UAC auto-elevating Batch wrapper
└── web/                   # Isolated Cloudflare Workers Web Profile Portal (.mobileconfig & .ovpn export)
```

> **Isolation Note:** `web/` is a standalone Cloudflare Worker (`workers-rs` + the 4-tab HTML/JS console in `web/assets/`). Desktop installers (`install-vpngate.sh`, `install-vpngate.ps1`, `install-vpngate.cmd`) build `vpngate-cli` and the separate `vpngate-gui` workspace inside an isolated temporary target directory. They never build, run, or copy `web/`; the root Cargo workspace **excludes** it.

---

## Attribution & Academic Credit

This project is an independent open-source client designed to interoperate with public relay servers operated by volunteers of the **[VPN Gate Academic Experiment Project](https://www.vpngate.net/en/about_us.aspx)** at the **Graduate School of Systems and Information Engineering, University of Tsukuba, Japan**, built upon **[SoftEther VPN](https://www.softether.org/)** open-source software.

This repository is **not** affiliated with or endorsed by the University of Tsukuba or SoftEther Corporation.

---

## Acceptable Use, Anti-Abuse & Legal Disclaimer

1. **Compliance with Local Laws & VPN Gate Anti-Abuse Policy**: Users are solely responsible for ensuring that accessing VPN Gate mirror portals and connecting to public VPN Gate volunteer relays complies with applicable local laws, network policies, and the [VPN Gate Anti-Abuse Policy](https://www.vpngate.net/en/about_abuse.aspx).
2. **Volunteer Relay Logging Notice**: Per the VPN Gate Academic Experiment Project's anti-abuse architecture, volunteer VPN Gate relay servers maintain connection logs to prevent network abuse and cybercrime. Do **not** use public VPN Gate relays for unauthorized access, spam, copyright infringement, or unlawful activity.
3. **No Warranty**: Provided `"AS IS"` under the [MIT License](LICENSE), without warranty of any kind.
