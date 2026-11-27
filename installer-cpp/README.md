# VPN Gate Connect platform installers

This directory contains one Qt 6 / C++20 installer application. Launch `vpngate-installer` with no arguments for the GUI; pass an action for headless CLI mode. The CLI defaults to the full host workflow on Linux, macOS, and Windows. Use `--user-only` for a per-user CLI install; the GUI remains per-user.

The C++ helper is the installer implementation packaged by the platform workflow. The former root-level shell, PowerShell, and batch installer entry points have been retired and removed from `main`; the package-generation helpers under `installer-cpp/packaging/` remain part of the build. Native CI builds and tests pass on Linux x64, Windows x64, and macOS x64/ARM64, but controlled host-level install, upgrade, rollback, and uninstall validation is still outstanding. Retirement of the old scripts does not claim full behavioral parity.

## Build

Requirements: CMake 3.16+, a C++20 compiler, and Qt 6.4+ Core and Widgets. Qt 6.9+ is required when building against the macOS 26 SDK.

```sh
cmake -S installer-cpp -B installer-cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build installer-cpp/build --parallel
ctest --test-dir installer-cpp/build --output-on-failure
```

The client payload is built from the existing Rust CLI and GUI projects. The full CLI workflow can bootstrap a temporary minimal Rust toolchain if Cargo is missing; `--keep-toolchain` requests a persistent toolchain. Windows selects native MSVC tools when available or MinGW-w64 for a GNU Rust target. Signing and GitHub Release publishing are not configured; the workflow artifacts are unsigned and expire after 14 days.

## Native CI installers

`.github/workflows/build-installers.yml` builds and tests the C++ helper on native Windows Server 2022, Ubuntu 24.04, macOS 15 Intel, and macOS 26 ARM64 runners. It produces one installer file per target: `vpngate-installer-windows-x64.msi`, `vpngate-installer-linux-x64.run`, and separate `vpngate-installer-macos-x64.pkg` / `vpngate-installer-macos-arm64.pkg` packages. The Windows MSI runs the helper as a deferred per-user custom action; Linux uses a self-extracting `.run`; macOS runs a `pkgbuild` postinstall action. The Actions artifacts are uploaded with `archive: false`, so each download is the installer itself, not an outer ZIP. GitHub Actions retains each artifact for 14 days. The workflow runs on relevant pushes to `feature/cpp-installer` or `main`, pull requests targeting `main`, or manual dispatch; it does not create release tags or GitHub Releases. On `main`, the artifact names are `vpngate-installer-windows-x64-msi`, `vpngate-installer-linux-x64-run`, `vpngate-installer-macos-x64-pkg`, and `vpngate-installer-macos-arm64-pkg`. Open the latest successful completed main-branch run to download one; artifacts are unsigned and retained for 14 days.

At install time the helper downloads the Rust source, builds the CLI and GUI, and installs them. It reuses an available Rust/Cargo toolchain and does not remove one that was already present. If Rust is missing, it bootstraps an isolated minimal toolchain and removes that temporary toolchain after the operation (`--remove-toolchain`); the existing full workflow also cleans up any temporary native compile packages it added. The Linux `.run` can be launched with `sh ./vpngate-installer-linux-x64.run` (or made executable with `chmod +x`); pass `uninstall` to the same file to remove the client. MSI uninstall runs the matching client cleanup action. The macOS `.pkg` is architecture-specific and unsigned; it retains its helper under `/Library/Application Support/VPN Gate Connect Installer` for later maintenance or uninstall. For example, uninstall the client with `sudo "/Library/Application Support/VPN Gate Connect Installer/vpngate-installer.app/Contents/MacOS/vpngate-installer" uninstall --yes`. On a macOS package install with no logged-in console user, the postinstall action skips optional Homebrew/OpenVPN provisioning rather than attempting to run Homebrew as root. These installers require network access and may require platform build prerequisites or administrator approval. Windows installs per-user and avoids machine-wide OpenVPN changes; Linux uses the existing full system workflow, while macOS runs it for the active console user and skips optional Homebrew/OpenVPN provisioning when no user is logged in.

All installers are unsigned. Passing CI packaging checks does not establish host-level safety or parity; controlled install, upgrade, rollback/failure, and uninstall tests on the target operating systems remain necessary. Artifacts are temporary workflow downloads, not permanent release assets.

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

## Validation boundary

The former root installer entry points are retired; the C++ helper and its packaging workflow are the current installer path. Linux Debug and Release builds plus CTest pass locally; native CI builds, core tests, Qt runtime deployment, architecture checks, and packaged CLI help smoke checks pass on Linux x64, Windows x64, and macOS x64/ARM64. No live privileged install/uninstall has been performed. GUI interaction and full Linux/Windows/macOS host-level install, upgrade, rollback/failure, and uninstall behavior still need controlled validation. Do not treat packaging CI as proof that every host integration is production-validated.
