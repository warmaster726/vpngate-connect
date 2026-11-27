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
| **`main`** | **Active (Default)** | Current desktop source (0.5.3); the platform-installer workflow publishes short-lived Actions artifacts, not GitHub Releases. |
| **`develop`** | **Integration** | Integration branch for changes that have not yet been merged to `main`. |

---

## Quick Installation

### Download a platform installer

The installers are published as **unsigned GitHub Actions artifacts**, not as permanent release downloads. Open the [main-branch installer workflow](https://github.com/warmaster726/vpngate-connect/actions/workflows/build-installers.yml?query=branch%3Amain), select the latest successful completed run on `main` (green check), and download the matching artifact. Artifacts expire after **14 days**; there is no stable direct installer URL. Each artifact is the installer file itself, with no extra ZIP wrapper.

Available packages:

- **Linux x64:** `vpngate-installer-linux-x64-run` — mark the downloaded `.run` executable and launch it:
  ```bash
  chmod +x vpngate-installer-linux-x64.run
  ./vpngate-installer-linux-x64.run
  ```
  To uninstall, run the same file with the `uninstall` argument: `./vpngate-installer-linux-x64.run uninstall`.
- **Windows x64:** `vpngate-installer-windows-x64-msi` — download and run the MSI. Uninstall through **Settings → Apps → Installed apps**.
- **macOS Intel:** `vpngate-installer-macos-x64-pkg`; **Apple Silicon:** `vpngate-installer-macos-arm64-pkg` — download the package matching the Mac and open it. These packages are unsigned, so macOS may require explicit approval before opening. To uninstall the client, run:
  ```bash
  sudo "/Library/Application Support/VPN Gate Connect Installer/vpngate-installer.app/Contents/MacOS/vpngate-installer" uninstall --yes
  ```

The current workflow provides Linux and Windows x64 packages and macOS x64/arm64 packages. Linux ARM64 and Windows ARM64 users can build from source using the instructions below.

---

### Building Manually From Source (Rust / Cargo)

The CLI action service uses pure-Rust TLS (`rustls`) and IKEv1 cryptography; it needs no OpenSSL headers. The native GUI is a separate eframe/egui Cargo workspace with its own lockfile. On Linux, building the GUI requires native X11/Wayland and fontconfig development libraries. A standard Rust toolchain and C linker are required for source builds.

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

Desktop 0.5.3 retains the 0.5.2 native-GUI workflow and progress improvements. Installer output is quieter: fatal argument/build/verification failures are reported as errors, routine macOS Command Line Tools setup as information, and the Windows missing-GUI condition is no longer warned twice.

- **VPN Gate Connect GUI** — run `vpngate-gui` for the eframe/egui interface on Linux, Windows 11, or macOS. It supports light/dark themes, connect, relay browsing, tools, status, diagnostics, watchdog, disconnect, and desktop update actions.
- **CLI action service** — run `vpngate --help` for the retained command/subcommand and operational flag reference. With no command, `vpngate` prints help; it does not open a terminal dashboard, GTK/VTE host, or Windows Terminal window.

Only the GUI uses the per-user OS-backed singleton lock. GUI command actions run through the companion `vpngate` binary, and short-lived service commands remain available while the GUI is open. Connect cancellation is operation-specific and retains rollback: cancelling a connection returns after VPN Gate tunnel/profile changes are rolled back or left unchanged.

The GUI checks for desktop updates anonymously at startup and after diagnostics. If a newer version is available, the GUI or interactive CLI offers to open the GitHub Actions installer workflow; choose the latest successful `main` run and download the matching platform artifact. The updater does **not** download or execute an installer automatically. Artifacts are unsigned, expire after 14 days, and are not permanent release downloads. `vpngate update -y` opens the workflow without a confirmation prompt. Privileged actions use Windows UAC, macOS authorization, or Linux `pkexec` where available. If a Linux system has no polkit agent, run a privileged CLI command from a terminal with `sudo` when required (for example, `sudo vpngate connect -c JP`).

The C++ platform installers build and install both the CLI service and native GUI. Linux installs the native GUI desktop entry; Windows creates one **VPN Gate Connect** GUI Start Menu shortcut. No GTK/VTE launcher is built or installed; the `vpngate` command remains available for CLI operations.

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
vpngate update                 # Check public main; open workflow for a newer installer
vpngate upgrade                # Same as `vpngate update`
```

The GUI checks for a newer desktop at **startup** and after diagnostics. Direct CLI `doctor` commands also check when run interactively unless `--no-update-check` is supplied. Version checks use anonymous HTTPS (no GitHub account or 2FA); **GitHub raw `main` is authoritative** and jsDelivr is only a fallback. If a newer version is found, the GUI or interactive CLI doctor can open the installer workflow. Select the latest successful completed `main` run, then download and run the matching artifact yourself. The updater never downloads or executes an installer automatically. Packages are unsigned and workflow artifacts expire after 14 days; no permanent installer download is published. Use `vpngate update -y` to open the workflow without a second prompt. Pool refresh stays `vpngate refresh`.

---

## Workspace Layout

```text
vpngate-connect/
├── crates/
│   ├── vpngate-core/      # Pure-Rust discovery, Official Mirrors, DoH, IKEv1/XFRM & desktop tunnel engine
│   ├── vpngate-cli/       # `vpngate` CLI command service for GUI and scripted use
│   └── vpngate-gui/       # Native eframe/egui GUI (`vpngate-gui`, separate Cargo workspace)
├── installer-cpp/         # Qt platform-installer helper and retained packaging/build helpers
├── .github/workflows/
│   └── build-installers.yml # Builds unsigned platform installer artifacts (14-day retention)
├── assets/                 # Desktop app icon (gate mark, no VG glyph) — SVG / PNG / Windows ICO
├── vpngate-gui.desktop     # Native VPN Gate Connect desktop entry
└── web/                    # Isolated Cloudflare Workers Web Profile Portal (.mobileconfig & .ovpn export)
```

> **Isolation Note:** `web/` is a standalone Cloudflare Worker (`workers-rs` + the HTML/JS console in `web/assets/`). The C++ platform-installer helper downloads the source and builds `vpngate-cli` and the separate `vpngate-gui` workspace; it does not build, run, or copy `web/`. The root Cargo workspace **excludes** it.
---

## Attribution & Academic Credit

This project is an independent open-source client designed to interoperate with public relay servers operated by volunteers of the **[VPN Gate Academic Experiment Project](https://www.vpngate.net/en/about_us.aspx)** at the **Graduate School of Systems and Information Engineering, University of Tsukuba, Japan**, built upon **[SoftEther VPN](https://www.softether.org/)** open-source software.

This repository is **not** affiliated with or endorsed by the University of Tsukuba or SoftEther Corporation.

---

## Acceptable Use, Anti-Abuse & Legal Disclaimer

1. **Compliance with Local Laws & VPN Gate Anti-Abuse Policy**: Users are solely responsible for ensuring that accessing VPN Gate mirror portals and connecting to public VPN Gate volunteer relays complies with applicable local laws, network policies, and the [VPN Gate Anti-Abuse Policy](https://www.vpngate.net/en/about_abuse.aspx).
2. **Volunteer Relay Logging Notice**: Per the VPN Gate Academic Experiment Project's anti-abuse architecture, volunteer VPN Gate relay servers maintain connection logs to prevent network abuse and cybercrime. Do **not** use public VPN Gate relays for unauthorized access, spam, copyright infringement, or unlawful activity.
3. **No Warranty**: Provided `"AS IS"` under the [MIT License](LICENSE), without warranty of any kind.
