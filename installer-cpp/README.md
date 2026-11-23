# VPN Gate Connect C++ installer (migration prototype)

This directory contains one Qt 6 / C++20 installer application. Launch `vpngate-installer` with no arguments for the GUI; pass an action to run the same executable in headless CLI mode.

## Build

Requirements: CMake 3.24+, a C++20 compiler, and Qt 6.4+ Core and Widgets.

```sh
cmake -S installer-cpp -B installer-cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build installer-cpp/build --parallel
ctest --test-dir installer-cpp/build --output-on-failure
```

The default GUI action uses the existing Rust CLI and GUI projects as its client payload. A native stable Rust/Cargo toolchain must already be available; this prototype does not install or bootstrap it. Cargo builds into a temporary directory, which is removed after the installer exits.

## CLI

```sh
# Inspect the plan without changing files or building the Rust client
vpngate-installer install --source /path/to/vpngate-connect --prefix "$HOME/.local" --dry-run

# Build the existing Rust client and install for the current user
vpngate-installer install --source /path/to/vpngate-connect --prefix "$HOME/.local" --yes

# Check the installed files against the SHA-256 inventory
vpngate-installer verify --prefix "$HOME/.local"

# Preview or perform a conservative uninstall
vpngate-installer uninstall --prefix "$HOME/.local" --dry-run
vpngate-installer uninstall --prefix "$HOME/.local" --yes
```

Without `--yes`, CLI install and uninstall do not change anything. `--force` permits replacement/removal of modified files that are already in the installer manifest; it does not expand cleanup to arbitrary files. The GUI confirms destructive actions and displays operation progress/output.

## Ownership and cleanup

The manifest records each client file installed by this application, its SHA-256 digest, and directories created under the install prefix. Uninstall removes only manifest-owned files that still match their recorded digest. Modified files are retained unless `--force` is explicitly selected. The manifest is validated against the product's supported install paths before any deletion, and symlinks/path traversal are refused. Empty installer-created directories are removed; unrelated files prevent their containing directories from being removed.

The uninstaller also removes the standard product-specific VPN Gate cache/config directories for the current user. Custom `VPNGATE_CACHE_DIR` or `--cache-dir` locations are not discoverable and are left untouched. Shared packages and system settings are not changed.

## Migration boundary

This is not yet a production replacement for `install-vpngate.sh` / `install-vpngate.ps1`. The current implementation is per-user only. Rust-toolchain bootstrapping, platform package installation, machine-wide VPN/NAT-T settings, migration/removal of legacy system-wide installs, Qt runtime deployment/signing, and OS-specific shortcuts/registration remain unported. Keep using the existing platform scripts for those workflows until those migration items are completed and tested on native Linux, Windows, and macOS hosts.
