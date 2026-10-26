#!/usr/bin/env bash
# Release-free deterministic iOS source builder for VPNGate Connect Mobile (macOS + Xcode).
# Compiles crates/vpngate-bridge (--release --locked) into mobile/ios/Frameworks/libvpngate_bridge.a.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IOS_FW_DIR="${SCRIPT_DIR}/ios/Frameworks"
RUST_ONLY=0
TARGET_TRIPLE="aarch64-apple-ios"

for arg in "$@"; do
    case "$arg" in
        --rust-only) RUST_ONLY=1 ;;
        --sim)
            if [[ "$(uname -m)" == "arm64" ]]; then
                TARGET_TRIPLE="aarch64-apple-ios-sim"
            else
                TARGET_TRIPLE="x86_64-apple-ios"
            fi
            ;;
        --help|-h)
            echo "Usage: ./build-ios.sh [--rust-only] [--sim]"
            exit 0
            ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "[!] iOS builds require macOS with Xcode installed." >&2
    exit 1
fi

if command -v rustup >/dev/null 2>&1; then
    rustup target add "$TARGET_TRIPLE" >/dev/null
fi

echo "[*] Compiling crates/vpngate-bridge (--release --locked) for ${TARGET_TRIPLE} ..."
(
    cd "$REPO_ROOT"
    cargo build --release --locked -p vpngate-bridge --target "$TARGET_TRIPLE"
)

mkdir -p "$IOS_FW_DIR"
cp -f "${REPO_ROOT}/target/${TARGET_TRIPLE}/release/libvpngate_bridge.a" \
    "${IOS_FW_DIR}/libvpngate_bridge.a"
echo "[+] Installed static Rust bridge: ${IOS_FW_DIR}/libvpngate_bridge.a"

if [[ "$RUST_ONLY" -eq 1 ]]; then
    exit 0
fi

cd "$SCRIPT_DIR"
flutter pub get
(cd ios && pod install)
flutter build ios --release --no-codesign
echo "[+] Unsigned iOS build ready under ${SCRIPT_DIR}/build/ios/iphoneos/Runner.app"
