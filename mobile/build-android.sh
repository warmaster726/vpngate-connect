#!/usr/bin/env bash
# Release-free deterministic Android source builder for VPNGate Connect Mobile.
# Compiles crates/vpngate-bridge (--release --locked) directly with the Android NDK
# LLVM toolchain (no GitHub Releases, no external codegen tools required).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JNI_LIBS_DIR="${SCRIPT_DIR}/android/app/src/main/jniLibs"
JNI_ONLY=0
ABIS_CSV="${VPNGATE_ANDROID_ABIS:-arm64-v8a,armeabi-v7a,x86_64}"

for arg in "$@"; do
    case "$arg" in
        --jni-only) JNI_ONLY=1 ;;
        --arm64-only) ABIS_CSV="arm64-v8a" ;;
        --help|-h)
            echo "Usage: ./build-android.sh [--jni-only] [--arm64-only]"
            exit 0
            ;;
    esac
done

if [[ -d /var/tmp && -w /var/tmp ]]; then
    export TMPDIR="${TMPDIR:-/var/tmp}"
fi

resolve_ndk_dir() {
    for cand in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${NDK_HOME:-}"; do
        if [[ -n "$cand" && -d "$cand/toolchains/llvm/prebuilt" ]]; then
            echo "$cand"
            return 0
        fi
    done
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "${HOME}/Android/Sdk" "${HOME}/Library/Android/sdk"; do
        if [[ -n "$sdk" && -d "$sdk/ndk" ]]; then
            local latest
            latest="$(ls -1 "$sdk/ndk" 2>/dev/null | sort -V | tail -n 1 || true)"
            if [[ -n "$latest" && -d "$sdk/ndk/$latest/toolchains/llvm/prebuilt" ]]; then
                echo "$sdk/ndk/$latest"
                return 0
            fi
        fi
    done
    return 1
}

NDK_DIR="$(resolve_ndk_dir || true)"
if [[ -z "$NDK_DIR" ]]; then
    echo "[!] Android NDK not found. Set ANDROID_NDK_HOME or install NDK via Android SDK Manager." >&2
    exit 1
fi

HOST_PREBUILT="$(ls -1d "${NDK_DIR}/toolchains/llvm/prebuilt/"* | head -n 1)"
LLVM_BIN="${HOST_PREBUILT}/bin"
API_LEVEL="${VPNGATE_ANDROID_API:-24}"

echo "[*] Using Android NDK: ${NDK_DIR}"
echo "[*] Compiling crates/vpngate-bridge (--release --locked) for ABIs: ${ABIS_CSV}"

IFS=',' read -r -a ABI_LIST <<< "$ABIS_CSV"
for abi in "${ABI_LIST[@]}"; do
    case "$abi" in
        arm64-v8a)
            TRIPLE="aarch64-linux-android"
            CLANG="${LLVM_BIN}/aarch64-linux-android${API_LEVEL}-clang"
            ENV_KEY="AARCH64_LINUX_ANDROID"
            ;;
        armeabi-v7a)
            TRIPLE="armv7-linux-androideabi"
            CLANG="${LLVM_BIN}/armv7a-linux-androideabi${API_LEVEL}-clang"
            ENV_KEY="ARMV7_LINUX_ANDROIDEABI"
            ;;
        x86_64)
            TRIPLE="x86_64-linux-android"
            CLANG="${LLVM_BIN}/x86_64-linux-android${API_LEVEL}-clang"
            ENV_KEY="X86_64_LINUX_ANDROID"
            ;;
        *)
            echo "[!] Unsupported Android ABI: $abi" >&2
            exit 1
            ;;
    esac

    if command -v rustup >/dev/null 2>&1; then
        rustup target add "$TRIPLE" >/dev/null
    fi

    export "CC_${TRIPLE//-/_}=${CLANG}"
    export "AR_${TRIPLE//-/_}=${LLVM_BIN}/llvm-ar"
    export "CARGO_TARGET_${ENV_KEY}_LINKER=${CLANG}"

    echo "[*] Building ${TRIPLE} -> jniLibs/${abi}/libvpngate_bridge.so ..."
    (
        cd "$REPO_ROOT"
        cargo build --release --locked -p vpngate-bridge --target "$TRIPLE"
    )

    mkdir -p "${JNI_LIBS_DIR}/${abi}"
    cp -f "${REPO_ROOT}/target/${TRIPLE}/release/libvpngate_bridge.so" \
        "${JNI_LIBS_DIR}/${abi}/libvpngate_bridge.so"
done

echo "[+] Packaged Rust C-ABI libraries under ${JNI_LIBS_DIR}"

if [[ "$JNI_ONLY" -eq 1 ]]; then
    exit 0
fi

cd "$SCRIPT_DIR"
flutter pub get
flutter build apk --release
echo "[+] Release APK ready: ${SCRIPT_DIR}/build/app/outputs/flutter-apk/app-release.apk"
