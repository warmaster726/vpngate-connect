# Platform-installer migration status

The C++ application is intended to become the sole installer implementation. `install-vpngate.sh`, `install-vpngate.ps1`, and `install-vpngate.cmd` must remain available until each platform reaches parity and passes native end-to-end testing; only then should the scripts become thin launchers for the release-built executable. The CI workflow now creates unsigned Windows and Linux bundles as 14-day workflow artifacts; it does not publish GitHub Releases. Code signing and release publishing remain separate work.

The CLI now defaults to the full host workflow on Linux, macOS, and Windows. The GUI remains per-user. Review with `--dry-run` before any real operation; mutation requires `--yes`. Confirmed POSIX system workflows use `sudo` when needed; Windows uses UAC for a non-admin full CLI workflow. The C++ host integrations are implemented but not yet proven at parity on native macOS or Windows.

## Existing behavior to preserve

| Area | POSIX shell (Linux/macOS) | PowerShell (Windows) | C++ status |
|---|---|---|---|
| Native architecture checks | x86_64/ARM64; reject Rosetta | x86_64/ARM64; reject x64 emulation | Checks are implemented for all three hosts; Linux and Windows native CI builds pass, macOS remains unbuilt |
| Source selection and CLI/GUI build | Local checkout or GitHub source archive; Rust build; optional temporary toolchain | Same, with MSVC/MinGW selection and rustup | Shared source/archive validation and toolchain flows are present; Windows/macOS toolchain paths remain unbuilt and untested |
| Legacy cleanup | Disconnect; product-specific processes/profiles/XFRM/nftables; old launchers and cache residue | Disconnect/RAS; old shims and OpenVPN processes; VPN profile/firewall residue | Platform-specific cleanup code exists for Linux, macOS, and Windows; native behavior and cleanup safety need testing |
| Runtime packages | apt/dnf/pacman or Homebrew; optional runtime tools | Optional headless OpenVPN via WinGet | Linux package managers, macOS Command Line Tools/Homebrew checks, and Windows WinGet OpenVPN handling are implemented; package operations have not been exercised live |
| Install registration | System binaries, desktop entry/icons/cache; stop conflicting L2TP services | LocalAppData, User PATH, NAT-T, OpenVPN hardening/firewall/TAP, Start Menu shortcut | Linux and macOS file layouts plus Windows PATH/shortcut/NAT-T/firewall/TAP flows are implemented; native install/upgrade tests are outstanding |
| Uninstall/restore | Optional `xl2tpd` purge, app paths/state, verify leftovers | Optional NAT-T override removal, PATH, VPN/firewall/profile, app/cache/shortcuts | Cleanup and residue checks exist on all platforms. Windows `--restore-natt` removes the override rather than restoring a saved prior value, matching the current PowerShell script behavior |
| Verification | Run `vpngate doctor`; report residue checks | Run `vpngate doctor`; host cleanliness check | Doctor and host residue checks are implemented; native macOS/Windows behavior is unverified |
| Script entry points | `install-vpngate.sh` | `install-vpngate.ps1` and `.cmd` wrapper | Retained unchanged; do not replace until the platform gates below pass |

## Safety and validation gates

- Keep the original platform scripts intact until every row above is implemented and tested on that platform. Do not present the C++ migration build as a production replacement yet.
- Preserve explicit dry-run/confirmation for privileged package, registry, firewall, network, and service operations. Review the consequences of all cleanup paths before running a real uninstall.
- Keep cleanup limited to product-specific artifacts and retain the C++ manifest/hash/path/symlink protections for managed client files. Host-level changes are outside that file manifest and must be checked separately.
- Linux Debug and Release builds plus CTest pass locally. Native Windows Release build, CTest, Qt runtime deployment, and packaged `--help` smoke test pass in CI. No live privileged install/uninstall has been performed.
- macOS has not been natively built. Windows GUI interaction and full Linux/Windows/macOS host-level install/upgrade/failure/uninstall parity remain unverified; runtime packaging CI is not a substitute for those checks.
- Before making the legacy scripts launchers, perform native architecture/build checks and compare dry-run plans to each script; then test clean install, upgrade, user-only behavior, failure/rollback, and uninstall on representative hosts. Verify residual files, profiles, registry values, firewall rules, packages, services, PATH, and shortcuts without disturbing unrelated user state.
