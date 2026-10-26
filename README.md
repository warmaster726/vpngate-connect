# vpngate-connect (`Cross-platform`)

Unified **Rust + Flutter** cross-platform architecture targeting **Windows, macOS, Linux, Android, and iOS**.

## Workspace Layout

```text
vpngate-connect/
├── Cargo.toml                  # Rust workspace root (release LTO & size-optimized profiles)
├── rust-toolchain.toml         # Stable Rust toolchain + rustfmt, clippy, rust-src
├── crates/
│   ├── vpngate-core/           # Shared engine: discovery, DoH, IKEv1/TCP probes, .ovpn/.mobileconfig, TUN engine
│   ├── vpngate-cli/            # Single-binary CLI + interactive TUI for Windows, macOS & Linux (`vpngate`)
│   └── vpngate-bridge/         # FFI bridge (`cdylib` / `staticlib`) for Flutter (`flutter_rust_bridge`)
└── mobile/                     # Flutter mobile shell for Android (`VpnService`) & iOS (`NEPacketTunnelProvider`)
```

## Quick Commands (Desktop / Core)

```sh
# Check, lint, and run unit tests across all workspace crates
cargo check --workspace
cargo clippy --workspace --all-targets
cargo test --workspace

# Run the desktop CLI binary
cargo run -p vpngate-cli
```

## License

Released under the [MIT License](LICENSE).
