# VPN Gate Connect C++ installer (migration build)

This directory contains one Qt 6 / C++20 installer application. Launch `vpngate-installer` with no arguments for the GUI; pass an action for headless CLI mode. The CLI defaults to the full host workflow on Linux, macOS, and Windows. Use `--user-only` for a per-user CLI install; the GUI remains per-user.

Host-integration implementations now exist for all three platforms, but only Linux has been built and unit-tested in this workspace. macOS and Windows still need native builds, parity review, and controlled side-effect tests. Keep `install-vpngate.sh`, `install-vpngate.ps1`, and `install-vpngate.cmd` until those checks pass.

## Build

Requirements: CMake 3.24+, a C++20 compiler, and Qt 6.4+ Core and Widgets.

```sh
cmake -S installer-cpp -B installer-cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build installer-cpp/build --parallel
ctest --test-dir installer-cpp/build --output-on-failure
```

The client payload is built from the existing Rust CLI and GUI projects. The full CLI workflow can bootstrap a temporary minimal Rust toolchain if Cargo is missing; `--keep-toolchain` requests a persistent toolchain. Windows selects native MSVC tools when available or MinGW-w64 for a GNU Rust target. Signing and release publishing are outside this migration work.

## Native CI bundles

`.github/workflows/build-installers.yml` builds and tests the app on native Windows Server 2022 and Ubuntu 24.04 runners. It packages `vpngate-installer-windows-x64.zip` (Qt runtime deployed with `windeployqt`) and `vpngate-installer-linux-x64.tar.gz` (a Qt-deployed AppDir), then uploads each as a 14-day GitHub Actions artifact. The workflow runs for relevant pushes to `feature/cpp-installer` or via `workflow_dispatch`; it does not create release tags or GitHub Releases. These bundles contain the C++ installer only: the Rust VPN client is downloaded/built when an install workflow is invoked. Passing CI packaging checks does not establish host-level parity or replace the legacy scripts.

## CLI

Preview a host-level install before changing the host:

```sh
vpngate-installer install --source /path/to/vpngate-connect --dry-run
```

Perform a confirmed install or uninstall:

```sh
vpngate-installer install --source /path/to/vpngate-connect --yes
vpngate-installer uninstall --yes
```

The confirmed POSIX workflow re-executes through `sudo` when necessary; Windows requests UAC elevation for a non-admin full CLI workflow. Review the plan first. Without `--yes`, install and uninstall do not make changes.

The per-user manifest-backed CLI workflow remains available:

```sh
vpngate-installer install --source /path/to/vpngate-connect \
  --prefix "$HOME/.local" --user-only --dry-run
vpngate-installer install --source /path/to/vpngate-connect \
  --prefix "$HOME/.local" --user-only --yes
vpngate-installer verify --prefix "$HOME/.local" --user-only
vpngate-installer uninstall --prefix "$HOME/.local" --user-only --dry-run
vpngate-installer uninstall --prefix "$HOME/.local" --user-only --yes
```

`--no-build` is only valid when a local checkout contains the required prebuilt client binaries. Other workflow options include `--skip-deps`, `--keep-toolchain`, `--remove-toolchain`, `--repo <owner/repo>`, `--branch <name>`, and `--cache-dir <dir>`. Windows also accepts `--skip-openvpn`, `--install-openvpn`, and `--restore-natt` (uninstall); Linux `--purge-packages` removes the dedicated `xl2tpd` helper only when requested.

`--force` permits replacement/removal of modified files already listed in the C++ installer manifest; it does not expand cleanup to arbitrary paths. `verify` checks the manifest-owned installation. The GUI confirms its per-user operations and displays progress/output.

## Host actions and ownership

The C++ file transaction records each managed client file, its SHA-256 digest, and installer-created directories. Uninstall removes only tracked files that still match their recorded digest. Modified files are retained unless `--force` is explicitly selected. Manifest paths are restricted to product-specific install locations; symlinks and traversal paths are refused. Host-level state is handled separately and is not represented by this file manifest.

- **Linux:** product-specific legacy session/profile/XFRM/nftables cleanup, runtime/build packages, selected L2TP/IPsec service handling, desktop/icon cache refresh, and a `vpngate doctor` readiness check.
- **macOS:** active-session and known-residue cleanup, Apple Command Line Tools checks, Homebrew OpenVPN handling, native install layouts, and a post-install doctor check.
- **Windows:** CLI UAC elevation, Rust/MSVC or MinGW toolchain setup, WinGet OpenVPN handling, RAS/profile and firewall cleanup, User PATH and Start Menu registration, NAT-T/service setup, optional TAP creation, and a doctor check.

These host actions have not all been validated on their native operating systems. On Windows, `--restore-natt` removes the PolicyAgent override, matching the existing PowerShell behavior; the installer does not save or restore a previously observed registry value. Package, registry, firewall, network, and service changes require `--yes`; use `--dry-run` first.

## Migration boundary — do not retire old scripts yet

The legacy entry points are intentionally retained. Linux Debug and Release builds, CTest, and diff checks pass in this workspace, but no live privileged install/uninstall has been performed. macOS and Windows branches have not been natively built or tested; GUI interaction, platform-native end-to-end flows, and C++/Qt runtime deployment also remain unverified. Compare each native workflow against the corresponding script and test install, upgrade, rollback/failure, and uninstall behavior before making the scripts thin launchers.
