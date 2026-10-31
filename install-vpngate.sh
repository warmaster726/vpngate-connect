#!/bin/sh
# install-vpngate.sh — One-step Linux & macOS Desktop Installer, Residue Cleaner & Uninstaller for `vpngate` (Rust Edition)
# POSIX /bin/sh (dash, sh, bash, zsh) compatible — works via `sh ./install-vpngate.sh`
# 64-bit native (x86_64 and aarch64/ARM64). No 32-bit. No Rosetta / ISA emulation.
# Priority: Auto (L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP) | Built-In Rust IKEv1 + Kernel XFRM + xl2tpd/ppp + OpenVPN
set -eu

main() {

if CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null; then
  SCRIPT_DIR="$(pwd)"
else
  SCRIPT_DIR="$(pwd)"
fi

MODE="install"
PURGE_PACKAGES=0
SKIP_DEPS=0
KEEP_TOOLCHAIN=0
TOOLCHAIN_POLICY=""
REPO_SLUG="${VPNGATE_REPO:-warmaster726/vpngate-connect}"
EDGE_BASE="${VPNGATE_EDGE:-}"
EDGE_BASE="${EDGE_BASE%/}"
HOST_UNAME="$(uname -s 2>/dev/null || echo Linux)"
HOST_MACHINE="$(uname -m 2>/dev/null || echo unknown)"
HOST_ARCH=""
RUST_HOST_TRIPLE=""
CALLER_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-}"
CALLER_CARGO_HOME="${CARGO_HOME:-}"
CALLER_RUSTUP_HOME="${RUSTUP_HOME:-}"

show_help() {
  cat <<'EOF'
Usage: sh ./install-vpngate.sh [OPTIONS]
   or: ./install-vpngate.sh [OPTIONS]

Installs, upgrades, or removes the single-binary Rust VPN Gate Desktop Suite
on Linux (Kali, Debian, Ubuntu, Mint, Pop!_OS, Fedora, Arch) and macOS.
64-bit native (x86_64 and ARM64/Apple Silicon). No 32-bit. No Rosetta. Compiles from source.

Options:
  (no arguments)       Clean legacy residues, install OS packages, build/install `vpngate`, wipe temp build cache, and run `doctor`
  --uninstall, -u      Disconnect active VPNs, remove binaries/launchers/caches, and verify zero residues
  --purge-packages     With --uninstall on Linux, also purge dedicated L2TP helper package (xl2tpd)
  --skip-apt           Skip system package installation step (alias: --skip-deps)
  --keep-toolchain     Keep compile tools (Rust toolchain and any C linker we install) after building `vpngate`
  --remove-toolchain   Remove compile tools after building `vpngate` (default when there is no prompt)
  --repo <owner/repo>  GitHub repository slug when downloading source archive outside a local checkout
  --help, -h           Show this help message and exit

When Rust (`cargo`) or a C linker (`gcc`) must be bootstrapped, an interactive
install asks whether to keep those compile tools or delete them after `vpngate`
is built. Pre-existing toolchains are never removed. Non-interactive runs
default to removing tools this installer added.
EOF
}

while [ "$#" -gt 0 ]; do
  arg="$1"
  shift
  case "$arg" in
    --uninstall|-u|uninstall|--remove)
      MODE="uninstall"
      ;;
    --purge-packages)
      PURGE_PACKAGES=1
      ;;
    --skip-apt|--skip-deps)
      SKIP_DEPS=1
      ;;
    --keep-toolchain)
      KEEP_TOOLCHAIN=1
      TOOLCHAIN_POLICY="keep"
      ;;
    --remove-toolchain)
      KEEP_TOOLCHAIN=0
      TOOLCHAIN_POLICY="remove"
      ;;
    --repo)
      [ "$#" -gt 0 ] || { echo "[!] Missing value for --repo" >&2; exit 2; }
      REPO_SLUG="$1"
      shift
      ;;
    --help|-h|help)
      show_help
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $arg" >&2
      echo "" >&2
      show_help >&2
      exit 2
      ;;
  esac
done

info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*"; }

# Try URLs in order. First non-empty 200 body wins (GitHub-bypass: Worker, then GitHub).
vg_fetch() {
  dest=$1
  shift
  for url in "$@"; do
    [ -n "${url}" ] || continue
    info "Trying ${url} ..."
    if curl -fsSL --connect-timeout 12 --max-time 120 "${url}" -o "${dest}" </dev/null \
      && [ -s "${dest}" ]; then
      return 0
    fi
    rm -f "${dest}"
  done
  return 1
}

read_user_line() {
  ans=""
  if [ -t 0 ]; then
    IFS= read -r ans || true
  elif [ -e /dev/tty ] && [ -r /dev/tty ]; then
    IFS= read -r ans </dev/tty || true
  else
    return 1
  fi
  REPLY_LINE="${ans}"
  return 0
}

resolve_compile_tool_policy() {
  tools_blob="$1"
  if [ "${TOOLCHAIN_POLICY}" = "keep" ]; then
    info "Compile tools will be kept after install (--keep-toolchain)."
    return
  fi
  if [ "${TOOLCHAIN_POLICY}" = "remove" ]; then
    info "Compile tools will be removed after compilation (--remove-toolchain)."
    return
  fi
  echo ""
  echo "VPN Gate Connect compiles from source and needs to install:${tools_blob}"
  echo ""
  echo "Keep these compile tools after VPN Gate Connect is installed?"
  echo "  [K] Keep them on this machine"
  echo "  [R] Remove them after compilation (default — only vpngate remains)"
  printf "Choice [R/k]: "
  REPLY_LINE=""
  if read_user_line; then
    echo ""
    case "${REPLY_LINE}" in
      [kK]|keep|Keep|KEEP|[yY]|yes|Yes)
        TOOLCHAIN_POLICY="keep"
        ok "Will keep compile tools after VPN Gate Connect is built."
        ;;
      *)
        TOOLCHAIN_POLICY="remove"
        ok "Will remove compile tools after VPN Gate Connect is built."
        ;;
    esac
  else
    echo "R"
    TOOLCHAIN_POLICY="remove"
    info "No interactive terminal — compile tools will be removed after the build."
    info "Re-run with --keep-toolchain to keep them, or --remove-toolchain to skip this notice."
  fi
}

detect_native_64bit() {
  case "${HOST_MACHINE}" in
    x86_64|amd64) HOST_ARCH="x86_64" ;;
    aarch64|arm64) HOST_ARCH="aarch64" ;;
    *)
      echo "[-] VPN Gate Connect desktop supports 64-bit x86_64 and ARM64 only (detected CPU: ${HOST_MACHINE})." >&2
      echo "    32-bit and other architectures are not supported." >&2
      exit 1
      ;;
  esac
  if [ "${HOST_UNAME}" = "Darwin" ]; then
    TRANSLATED="$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)"
    if [ "${TRANSLATED}" = "1" ]; then
      echo "[-] This installer is running under Rosetta (x86_64 translation)." >&2
      echo "    On Apple Silicon run it natively:  arch -arm64 sh ./install-vpngate.sh" >&2
      exit 1
    fi
    ARM64_CPU="$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)"
    if [ "${ARM64_CPU}" = "1" ]; then
      HOST_ARCH="aarch64"
    fi
  fi
  if [ "${HOST_UNAME}" = "Darwin" ]; then
    if [ "${HOST_ARCH}" = "aarch64" ]; then
      RUST_HOST_TRIPLE="aarch64-apple-darwin"
    else
      RUST_HOST_TRIPLE="x86_64-apple-darwin"
    fi
  else
    if [ "${HOST_ARCH}" = "aarch64" ]; then
      RUST_HOST_TRIPLE="aarch64-unknown-linux-gnu"
    else
      RUST_HOST_TRIPLE="x86_64-unknown-linux-gnu"
    fi
  fi
}

if [ "${MODE}" = "install" ]; then
  detect_native_64bit
fi

if [ "$(id -u)" -eq 0 ]; then
  sudo() { "$@"; }
elif ! command -v sudo >/dev/null 2>&1; then
  warn "Root privileges are required (and 'sudo' was not found). Please run as root."
  exit 1
elif [ ! -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
  # shellcheck disable=SC2024
  sudo -v </dev/tty
fi

TARGET_USER="${SUDO_USER:-${USER:-$(id -un)}}"
TARGET_HOME=""
if command -v getent >/dev/null 2>&1; then
  TARGET_HOME="$(getent passwd "${TARGET_USER}" 2>/dev/null | cut -d: -f6 || true)"
fi
if [ -z "${TARGET_HOME}" ] || [ ! -d "${TARGET_HOME}" ]; then
  if [ "${HOST_UNAME}" = "Darwin" ] && [ -d "/Users/${TARGET_USER}" ]; then
    TARGET_HOME="/Users/${TARGET_USER}"
  else
    TARGET_HOME="${HOME:-/root}"
  fi
fi
TARGET_UID="$(id -u "${TARGET_USER}" 2>/dev/null || echo "")"
TARGET_GID="$(id -g "${TARGET_USER}" 2>/dev/null || echo "")"

if [ "${HOST_UNAME}" = "Darwin" ]; then
  USER_CACHE_DIR="${TARGET_HOME}/Library/Caches/vpngate"
else
  USER_CACHE_DIR="${TARGET_HOME}/.cache/vpngate"
fi

NL='
'
CLEANED_COUNT=0
CLEANED_LIST=""
INSTALL_TMP_ROOT=""

record_cleaned() {
  CLEANED_COUNT=$((CLEANED_COUNT + 1))
  if [ -z "${CLEANED_LIST}" ]; then
    CLEANED_LIST="    - $1"
  else
    CLEANED_LIST="${CLEANED_LIST}${NL}    - $1"
  fi
}

install_lf_file() {
  src_file="$1"
  dst_file="$2"
  file_mode="$3"
  stage_parent="/tmp"
  if [ -n "${INSTALL_TMP_ROOT}" ] && [ -d "${INSTALL_TMP_ROOT}" ]; then
    stage_parent="${INSTALL_TMP_ROOT}"
  fi
  tmp_stage="$(mktemp "${stage_parent}/vpngate-stage.XXXXXX")"
  tr -d '\r' < "${src_file}" > "${tmp_stage}"
  sudo install -m "${file_mode}" "${tmp_stage}" "${dst_file}"
  rm -f "${tmp_stage}"
}

cleanup_previous_residues() {
  info "Scanning system for active sessions and residues from previous vpngate installations ..."

  # 1. Gracefully disconnect via installed Rust `vpngate`
  for cache_cand in "${USER_CACHE_DIR}" "/root/.cache/vpngate"; do
    sudo test -d "${cache_cand}" || continue
    if sudo test -f "${cache_cand}/active_state.json" ||
       sudo test -f "${cache_cand}/openvpn.pid" ||
       sudo test -f "${cache_cand}/monitor.pid" ||
       sudo test -d "/run/vpngate-l2tp"; then
      if [ -x /usr/local/bin/vpngate ] && [ ! -L /usr/local/bin/vpngate ]; then
        sudo env VPNGATE_CACHE_DIR="${cache_cand}" /usr/local/bin/vpngate disconnect --no-resize >/dev/null 2>&1 || true
        record_cleaned "Disconnected active/stale Rust vpngate session (${cache_cand})"
      fi
    fi
  done

  # 2. Terminate orphaned background daemons (_monitor, _ikev1, vpngate-launcher, openvpn, xl2tpd, pppd) on Linux.
  # Never kill this installer or its ancestors (the GUI vpngate-launcher / VTE
  # vpngate). Doing so SIGHUPs the in-place upgrade and the window just closes.
  if [ -d /proc ]; then
    vg_killed_procs="$(
      sudo VG_SELF="$$" VG_PPID="${PPID:-0}" /bin/sh -c '
        vg_is_protected() {
          vg_cand="$1"
          [ "${vg_cand}" = "$$" ] && return 0
          vg_walk="$$"
          vg_hops=0
          while [ -n "${vg_walk}" ] && [ "${vg_walk}" != "0" ] && [ "${vg_hops}" -lt 64 ]; do
            [ "${vg_cand}" = "${vg_walk}" ] && return 0
            [ "${vg_cand}" = "${VG_SELF}" ] && return 0
            [ "${vg_cand}" = "${VG_PPID}" ] && return 0
            vg_next=""
            if [ -r "/proc/${vg_walk}/status" ]; then
              vg_next="$(awk "/^PPid:/ {print \$2; exit}" "/proc/${vg_walk}/status" 2>/dev/null || true)"
            fi
            [ -n "${vg_next}" ] || break
            [ "${vg_next}" = "${vg_walk}" ] && break
            vg_walk="${vg_next}"
            vg_hops=$((vg_hops + 1))
          done
          [ "${vg_cand}" = "${VG_SELF}" ] || [ "${vg_cand}" = "${VG_PPID}" ]
        }
        vg_killed=""
        vg_term_pids=""
        for vg_proc in /proc/[0-9]*; do
          vg_pid="${vg_proc#/proc/}"
          vg_is_protected "${vg_pid}" && continue
          [ -r "${vg_proc}/cmdline" ] || continue
          vg_cmd="$(tr "\0" " " < "${vg_proc}/cmdline" 2>/dev/null || true)"
          [ -n "${vg_cmd}" ] || continue
          case "${vg_cmd}" in
            *install-vpngate*) continue ;;
          esac
          vg_exe="${vg_cmd%% *}"
          vg_base="${vg_exe##*/}"
          vg_hit=""
          case "${vg_cmd}" in
            *vpngate-launcher*) vg_hit="vpngate-launcher(pid=${vg_pid})" ;;
          esac
          if [ -z "${vg_hit}" ]; then
            case " ${vg_cmd} " in
              *" _monitor "*|*" _ikev1 "*)
                case "${vg_cmd}" in
                  *vpngate*) vg_hit="vpngate-daemon(pid=${vg_pid})" ;;
                esac
                ;;
            esac
          fi
          if [ -z "${vg_hit}" ] && [ "${vg_base}" = "openvpn" ]; then
            case "${vg_cmd}" in
              *vpngate-*|*"/vpngate/"*) vg_hit="openvpn(pid=${vg_pid})" ;;
            esac
          fi
          if [ -z "${vg_hit}" ] && { [ "${vg_base}" = "xl2tpd" ] || [ "${vg_base}" = "pppd" ]; }; then
            case "${vg_cmd}" in
              *"/run/vpngate-l2tp"*) vg_hit="${vg_base}(pid=${vg_pid})" ;;
            esac
          fi
          [ -n "${vg_hit}" ] || continue
          kill -TERM "${vg_pid}" 2>/dev/null || true
          vg_term_pids="${vg_term_pids} ${vg_pid}"
          if [ -n "${vg_killed}" ]; then
            vg_killed="${vg_killed}, ${vg_hit}"
          else
            vg_killed="${vg_hit}"
          fi
        done
        if [ -n "${vg_term_pids}" ]; then
          sleep 1
          for vg_pid in ${vg_term_pids}; do
            kill -KILL "${vg_pid}" 2>/dev/null || true
          done
          printf "%s" "${vg_killed}"
        fi
      ' 2>/dev/null || true
    )"
    if [ -n "${vg_killed_procs}" ]; then
      record_cleaned "Stopped orphaned background process(es): ${vg_killed_procs}"
    fi
  fi

  # 3. Remove leftover NetworkManager vpngate-* profiles
  if command -v nmcli >/dev/null 2>&1; then
    vg_nm_lines="$(nmcli -t -f UUID,NAME,TYPE connection show 2>/dev/null || true)"
    if [ -n "${vg_nm_lines}" ]; then
      vg_old_ifs="${IFS}"
      IFS="${NL}"
      for vg_nm_line in ${vg_nm_lines}; do
        IFS="${vg_old_ifs}"
        vg_uuid="${vg_nm_line%%:*}"
        vg_rem="${vg_nm_line#*:}"
        vg_name="${vg_rem%%:*}"
        case "${vg_name}" in
          vpngate-*)
            if [ -n "${vg_uuid}" ]; then
              sudo nmcli --wait 5 connection down uuid "${vg_uuid}" >/dev/null 2>&1 || true
              sudo nmcli connection delete uuid "${vg_uuid}" >/dev/null 2>&1 || true
              record_cleaned "Removed NetworkManager profile: ${vg_name}"
            fi
            ;;
        esac
      done
      IFS="${vg_old_ifs}"
    fi
  fi

  # 4. Clean Linux XFRM policies/states & native nftables `vpngate-l2tp` handles (without polluting nftables via iptables)
  if [ "${HOST_UNAME}" = "Linux" ]; then
    if command -v ip >/dev/null 2>&1; then
      if sudo ip xfrm policy 2>/dev/null | grep -q "priority 1701"; then
        sudo ip xfrm policy deleteall priority 1701 >/dev/null 2>&1 || true
        record_cleaned "Cleared kernel XFRM policies (priority 1701)"
      fi
      if sudo ip xfrm state 2>/dev/null | grep -q "reqid 17010"; then
        sudo ip xfrm state deleteall reqid 17010 >/dev/null 2>&1 || true
        record_cleaned "Cleared kernel XFRM ESP states (reqid 17010)"
      fi
    fi

    if command -v nft >/dev/null 2>&1; then
      vg_nft_handles="$(sudo nft -a list chain inet filter input 2>/dev/null | awk '/vpngate-l2tp/ {print $NF}' || true)"
      if [ -n "${vg_nft_handles}" ]; then
        for h in ${vg_nft_handles}; do
          case "${h}" in
            ''|*[!0-9]*) ;;
            *) sudo nft delete rule inet filter input handle "${h}" >/dev/null 2>&1 || true ;;
          esac
        done
        record_cleaned "Removed temporary nftables rules (comment: vpngate-l2tp)"
      fi
    fi

    # Remove legacy Python v5.3 `/usr/local/bin/vpngate.py` script & `__pycache__`
    if [ -e /usr/local/bin/vpngate.py ] || [ -L /usr/local/bin/vpngate.py ]; then
      sudo rm -f /usr/local/bin/vpngate.py
      record_cleaned "Removed legacy Python script: /usr/local/bin/vpngate.py"
    fi
    if [ -d /usr/local/bin/__pycache__ ]; then
      sudo rm -rf /usr/local/bin/__pycache__
      record_cleaned "Removed /usr/local/bin/__pycache__"
    fi
    if [ -d /run/vpngate-l2tp ]; then
      sudo rm -rf /run/vpngate-l2tp
      record_cleaned "Removed stale runtime directory: /run/vpngate-l2tp"
    fi
  fi

  # 5. Remove duplicate user-local shadow binaries/desktop entries
  for shadow_item in \
    "${TARGET_HOME}/.local/bin/vpngate" \
    "${TARGET_HOME}/.local/bin/vpngate.py" \
    "${TARGET_HOME}/.local/bin/vpngate-launcher" \
    "${TARGET_HOME}/.local/bin/vpngate-launcher.py" \
    "${TARGET_HOME}/.local/share/applications/vpngate.desktop" \
    "/root/.local/share/applications/vpngate.desktop"; do
    if sudo test -e "${shadow_item}" || sudo test -L "${shadow_item}"; then
      sudo rm -f "${shadow_item}"
      record_cleaned "Removed shadow user-local artifact: ${shadow_item}"
    fi
  done

  # 6. Clean transient cache files (.pid, .ovpn, .tmp, active_state.json, ui_socks)
  for cdir in "${USER_CACHE_DIR}" "/root/.cache/vpngate"; do
    sudo test -d "${cdir}" || continue
    for tname in active_state.json ikev1_state.json ikev1.pid openvpn.pid monitor.pid l2tp_route.json resolv.conf.bak ui_socks; do
      if sudo test -e "${cdir}/${tname}" || sudo test -L "${cdir}/${tname}"; then
        sudo rm -rf "${cdir}/${tname}"
      fi
    done
    sudo find "${cdir}" -maxdepth 1 \( -name '*.ovpn' -o -name '*.tmp' -o -name '*.bak' \) -delete 2>/dev/null || true
  done
}

# ==============================================================================
# UNINSTALL MODE (`sh ./install-vpngate.sh --uninstall`)
# ==============================================================================
if [ "${MODE}" = "uninstall" ]; then
  info "Starting VPN Gate uninstallation ..."
  cleanup_previous_residues

  for bin_target in \
    /usr/local/bin/vpngate \
    /usr/local/bin/vpngate.py \
    /usr/local/bin/vpngate-launcher \
    /usr/local/bin/vpngate-launcher.py; do
    if [ -e "${bin_target}" ] || [ -L "${bin_target}" ]; then
      sudo rm -f "${bin_target}"
      record_cleaned "Removed installed executable/symlink: ${bin_target}"
    fi
  done

  if [ -e /usr/share/applications/vpngate.desktop ] || [ -L /usr/share/applications/vpngate.desktop ]; then
    sudo rm -f /usr/share/applications/vpngate.desktop
    record_cleaned "Removed GNOME desktop launcher: /usr/share/applications/vpngate.desktop"
  fi
  if command -v update-desktop-database >/dev/null 2>&1; then
    sudo update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
  fi
  ICON_REMOVED=0
  if [ -e /usr/share/icons/hicolor/scalable/apps/vpngate.svg ] || [ -L /usr/share/icons/hicolor/scalable/apps/vpngate.svg ]; then
    sudo rm -f /usr/share/icons/hicolor/scalable/apps/vpngate.svg
    ICON_REMOVED=1
  fi
  for sz in 16 24 32 48 64 128 256 512; do
    ico_png="/usr/share/icons/hicolor/${sz}x${sz}/apps/vpngate.png"
    if [ -e "${ico_png}" ] || [ -L "${ico_png}" ]; then
      sudo rm -f "${ico_png}"
      ICON_REMOVED=1
    fi
  done
  if [ -e /usr/share/pixmaps/vpngate.png ] || [ -L /usr/share/pixmaps/vpngate.png ]; then
    sudo rm -f /usr/share/pixmaps/vpngate.png
    ICON_REMOVED=1
  fi
  if [ "${ICON_REMOVED}" -eq 1 ]; then
    record_cleaned "Removed VPN Gate Connect app icon"
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
      sudo gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
    fi
  fi

  for dir_target in \
    "${USER_CACHE_DIR}" \
    "${TARGET_HOME}/.config/vpngate" \
    "/root/.cache/vpngate" \
    "/root/.config/vpngate"; do
    if sudo test -d "${dir_target}"; then
      sudo rm -rf "${dir_target}"
      record_cleaned "Removed cache/config directory: ${dir_target}"
    fi
  done

  if [ "${PURGE_PACKAGES}" -eq 1 ] && [ "${HOST_UNAME}" = "Linux" ]; then
    info "Purging dedicated L2TP helper package (xl2tpd) as requested ..."
    if command -v apt-get >/dev/null 2>&1; then
      sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y xl2tpd >/dev/null 2>&1 || true
      sudo env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf remove -y xl2tpd >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
      sudo pacman -Rns --noconfirm xl2tpd >/dev/null 2>&1 || true
    fi
    record_cleaned "Purged system package: xl2tpd"
  fi

  echo ""
  if [ "${CLEANED_COUNT}" -gt 0 ]; then
    ok "Cleaned ${CLEANED_COUNT} item(s):"
    printf '%s\n' "${CLEANED_LIST}"
  else
    ok "No vpngate installation or residues were present on this system."
  fi

  LEFTOVER_COUNT=0
  LEFTOVER_LIST=""
  for check_path in \
    /usr/local/bin/vpngate \
    /usr/local/bin/vpngate.py \
    /usr/local/bin/vpngate-launcher \
    /usr/local/bin/vpngate-launcher.py \
    /usr/share/applications/vpngate.desktop \
    /usr/share/icons/hicolor/scalable/apps/vpngate.svg \
    /usr/share/pixmaps/vpngate.png \
    /run/vpngate-l2tp \
    "${USER_CACHE_DIR}" \
    "/root/.cache/vpngate"; do
    if sudo test -e "${check_path}" || sudo test -L "${check_path}"; then
      LEFTOVER_COUNT=$((LEFTOVER_COUNT + 1))
      LEFTOVER_LIST="${LEFTOVER_LIST} ${check_path}"
    fi
  done

  echo ""
  if [ "${LEFTOVER_COUNT}" -eq 0 ]; then
    ok "Verification PASSED: VPN Gate has been completely removed with zero remaining residues."
  else
    warn "Verification noticed remaining path(s):${LEFTOVER_LIST}"
    exit 1
  fi
  exit 0
fi

# ==============================================================================
# INSTALL / UPGRADE MODE (`sh ./install-vpngate.sh`)
# ==============================================================================
HAD_CC=0
if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
  HAD_CC=1
fi
HAD_CARGO=0
if [ -n "${CALLER_CARGO_HOME}" ] && [ -x "${CALLER_CARGO_HOME}/bin/cargo" ]; then
  HAD_CARGO=1
elif [ -x "${TARGET_HOME}/.cargo/bin/cargo" ]; then
  HAD_CARGO=1
elif command -v cargo >/dev/null 2>&1; then
  HAD_CARGO=1
fi

WILL_COMPILE=1
if [ ! -f "${SCRIPT_DIR}/Cargo.toml" ] && [ -x "${SCRIPT_DIR}/vpngate" ]; then
  WILL_COMPILE=0
fi

NEED_RUST=0
NEED_CC_PKG=0
if [ "${WILL_COMPILE}" -eq 1 ]; then
  if [ "${HAD_CARGO}" -eq 0 ]; then
    NEED_RUST=1
  fi
  if [ "${HAD_CC}" -eq 0 ] && [ "${SKIP_DEPS}" -eq 0 ] && [ "${HOST_UNAME}" != "Darwin" ]; then
    NEED_CC_PKG=1
  fi
fi

if [ "${NEED_RUST}" -eq 1 ] || [ "${NEED_CC_PKG}" -eq 1 ]; then
  TOOLS_LIST=""
  if [ "${NEED_RUST}" -eq 1 ]; then
    TOOLS_LIST="${TOOLS_LIST}
  - Rust toolchain (rustup, cargo, rustc) — used only to compile vpngate"
  fi
  if [ "${NEED_CC_PKG}" -eq 1 ]; then
    TOOLS_LIST="${TOOLS_LIST}
  - C linker (gcc) — required to link the desktop binary"
  fi
  resolve_compile_tool_policy "${TOOLS_LIST}"
  if [ "${TOOLCHAIN_POLICY}" = "keep" ]; then
    KEEP_TOOLCHAIN=1
  else
    KEEP_TOOLCHAIN=0
    TOOLCHAIN_POLICY="remove"
  fi
fi

INSTALLED_COMPILE_PKGS=""

TMP_PARENT="/var/tmp"
[ -d "${TMP_PARENT}" ] && [ -w "${TMP_PARENT}" ] || TMP_PARENT="/tmp"
INSTALL_TMP_ROOT="$(mktemp -d "${TMP_PARENT}/vpngate-install.XXXXXX")"
if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
  chown "${TARGET_UID}:${TARGET_GID:-${TARGET_UID}}" "${INSTALL_TMP_ROOT}" 2>/dev/null || chown "${TARGET_USER}" "${INSTALL_TMP_ROOT}" 2>/dev/null || true
fi

cleanup_install_tmp() {
  if [ -n "${INSTALL_TMP_ROOT}" ] && [ -e "${INSTALL_TMP_ROOT}" ]; then
    rm -rf "${INSTALL_TMP_ROOT}" 2>/dev/null || sudo rm -rf "${INSTALL_TMP_ROOT}" 2>/dev/null || true
  fi
}
trap cleanup_install_tmp EXIT INT TERM HUP

cleanup_previous_residues
if [ "${CLEANED_COUNT}" -gt 0 ]; then
  ok "Pre-install cleanup resolved ${CLEANED_COUNT} residue(s):"
  printf '%s\n' "${CLEANED_LIST}"
else
  ok "Pre-install check clean: no legacy residues detected."
fi

# 1. Install OS tunnel runtime & GNOME window dependencies (not compile-only tools)
if [ "${SKIP_DEPS}" -eq 0 ]; then
  if [ "${HOST_UNAME}" = "Darwin" ]; then
    if ! xcode-select -p >/dev/null 2>&1; then
      warn "Apple Command Line Tools ('cc' linker) not found. Launching 'xcode-select --install' ..."
      warn "Command Line Tools stay on the Mac; this installer will not remove them."
      xcode-select --install || true
    fi
    if command -v brew >/dev/null 2>&1; then
      info "Ensuring OpenVPN is installed via Homebrew ..."
      sudo -u "${TARGET_USER}" brew list openvpn >/dev/null 2>&1 || sudo -u "${TARGET_USER}" brew install openvpn
    fi
  elif command -v apt-get >/dev/null 2>&1; then
    info "Installing required OpenVPN, L2TP/PPP & runtime packages via apt-get ..."
    sudo apt-get update -qq </dev/null
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o APT::Keep-Downloaded-Packages=false \
      openvpn \
      xl2tpd \
      ppp \
      iproute2 \
      curl \
      ca-certificates \
      tar </dev/null
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o APT::Keep-Downloaded-Packages=false --no-install-recommends \
      libgtk-4-1 \
      libvte-2.91-gtk4-0 \
      network-manager-openvpn \
      network-manager-openvpn-gnome \
      libnotify-bin </dev/null 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    info "Installing required OpenVPN, L2TP/PPP & runtime packages via dnf ..."
    sudo dnf install -y openvpn xl2tpd ppp iproute curl ca-certificates tar </dev/null
    sudo dnf install -y NetworkManager-openvpn NetworkManager-openvpn-gnome libnotify gtk4 vte291-gtk4 </dev/null 2>/dev/null || true
  elif command -v pacman >/dev/null 2>&1; then
    info "Installing required OpenVPN, L2TP/PPP & runtime packages via pacman ..."
    sudo pacman -Sy --needed --noconfirm openvpn xl2tpd ppp iproute2 curl ca-certificates tar </dev/null
    sudo pacman -S --needed --noconfirm networkmanager-openvpn libnotify gtk4 vte4 </dev/null 2>/dev/null || true
  fi
fi

# 1b. Compile-only C linker — installed only if missing; removable after the build
if [ "${NEED_CC_PKG}" -eq 1 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    for cc_pkg in gcc libc6-dev; do
      if ! dpkg-query -W -f='${Status}' "${cc_pkg}" 2>/dev/null | grep -q 'install ok installed'; then
        INSTALLED_COMPILE_PKGS="${INSTALLED_COMPILE_PKGS} ${cc_pkg}"
      fi
    done
    info "Installing compile-only C linker packages (gcc) ..."
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o APT::Keep-Downloaded-Packages=false gcc libc6-dev </dev/null
  elif command -v dnf >/dev/null 2>&1; then
    for cc_pkg in gcc glibc-devel; do
      if ! rpm -q "${cc_pkg}" >/dev/null 2>&1; then
        INSTALLED_COMPILE_PKGS="${INSTALLED_COMPILE_PKGS} ${cc_pkg}"
      fi
    done
    info "Installing compile-only C linker packages (gcc) ..."
    sudo dnf install -y gcc glibc-devel </dev/null
  elif command -v pacman >/dev/null 2>&1; then
    if ! pacman -Q gcc >/dev/null 2>&1; then
      INSTALLED_COMPILE_PKGS="${INSTALLED_COMPILE_PKGS} gcc"
    fi
    info "Installing compile-only C linker packages (gcc) ..."
    sudo pacman -S --needed --noconfirm gcc </dev/null
  fi
fi

# 1c. Linux GTK4/VTE headers — compile-only, needed to build vpngate-launcher
if [ "${HOST_UNAME}" = "Linux" ] && [ "${SKIP_DEPS}" -eq 0 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    for gtk_pkg in libgtk-4-dev libvte-2.91-gtk4-dev pkg-config; do
      if ! dpkg-query -W -f='${Status}' "${gtk_pkg}" 2>/dev/null | grep -q 'install ok installed'; then
        INSTALLED_COMPILE_PKGS="${INSTALLED_COMPILE_PKGS} ${gtk_pkg}"
      fi
    done
    info "Installing compile-only GTK4/VTE headers for vpngate-launcher ..."
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o APT::Keep-Downloaded-Packages=false \
      libgtk-4-dev libvte-2.91-gtk4-dev pkg-config </dev/null
  elif command -v dnf >/dev/null 2>&1; then
    for gtk_pkg in gtk4-devel vte291-gtk4-devel pkgconf-pkg-config; do
      if ! rpm -q "${gtk_pkg}" >/dev/null 2>&1; then
        INSTALLED_COMPILE_PKGS="${INSTALLED_COMPILE_PKGS} ${gtk_pkg}"
      fi
    done
    sudo dnf install -y gtk4-devel vte291-gtk4-devel pkgconf-pkg-config </dev/null 2>/dev/null || true
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed --noconfirm gtk4 vte4 pkgconf </dev/null 2>/dev/null || true
  fi
fi

# 2. Locate local workspace / prebuilt binary, or fetch `main` source archive from GitHub (Release-free!)
WORK_SRC_DIR="${SCRIPT_DIR}"
BIN_SRC=""
LAUNCHER_SRC=""
HAD_LOCAL_TARGET=0
if [ -e "${WORK_SRC_DIR}/target" ]; then
  HAD_LOCAL_TARGET=1
fi
HAD_EXISTING_CARGO=0
USED_EPHEMERAL_RUSTUP=0

if [ ! -f "${WORK_SRC_DIR}/Cargo.toml" ] && [ ! -x "${WORK_SRC_DIR}/vpngate" ]; then
  BRANCH_NAME="${VPNGATE_BRANCH:-main}"
  SRC_STAGE_DIR="${INSTALL_TMP_ROOT}/src"
  mkdir -p "${SRC_STAGE_DIR}"
  info "Fetching source archive (Cloudflare Worker, then GitHub) ..."
  if ! vg_fetch "${SRC_STAGE_DIR}/src.tar.gz" \
      ${EDGE_BASE:+"${EDGE_BASE}/src.tar.gz"} \
      "https://codeload.github.com/${REPO_SLUG}/tar.gz/refs/heads/${BRANCH_NAME}" \
      "https://github.com/${REPO_SLUG}/archive/refs/heads/${BRANCH_NAME}.tar.gz"; then
    warn "Could not download source archive. Set VPNGATE_EDGE to your workers.dev origin or clone the repo locally."
    exit 1
  fi
  tar -xzf "${SRC_STAGE_DIR}/src.tar.gz" -C "${SRC_STAGE_DIR}"
  rm -f "${SRC_STAGE_DIR}/src.tar.gz"
  EXTRACTED_DIR="$(find "${SRC_STAGE_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [ -z "${EXTRACTED_DIR}" ] || [ ! -f "${EXTRACTED_DIR}/Cargo.toml" ]; then
    warn "Downloaded source archive did not contain Cargo.toml."
    exit 1
  fi
  if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
    chown -R "${TARGET_UID}:${TARGET_GID:-${TARGET_UID}}" "${EXTRACTED_DIR}" 2>/dev/null || chown -R "${TARGET_USER}" "${EXTRACTED_DIR}" 2>/dev/null || true
  fi
  WORK_SRC_DIR="${EXTRACTED_DIR}"
fi

if [ -f "${WORK_SRC_DIR}/Cargo.toml" ]; then
  CARGO_BIN=""
  BUILD_RUSTUP_HOME="${CALLER_RUSTUP_HOME}"
  BUILD_CARGO_HOME="${CALLER_CARGO_HOME}"

  if [ -n "${CALLER_CARGO_HOME}" ] && [ -x "${CALLER_CARGO_HOME}/bin/cargo" ]; then
    CARGO_BIN="${CALLER_CARGO_HOME}/bin/cargo"
    HAD_EXISTING_CARGO=1
  elif [ -x "${TARGET_HOME}/.cargo/bin/cargo" ]; then
    CARGO_BIN="${TARGET_HOME}/.cargo/bin/cargo"
    HAD_EXISTING_CARGO=1
  elif command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
    HAD_EXISTING_CARGO=1
  fi

  if [ -z "${CARGO_BIN}" ]; then
    RUSTUP_SH="${INSTALL_TMP_ROOT}/rustup-init.sh"
    if ! vg_fetch "${RUSTUP_SH}" \
        "https://sh.rustup.rs" \
        "https://static.rust-lang.org/rustup/rustup-init.sh" \
        "https://rsproxy.cn/rustup-init.sh"; then
      warn "Could not download rustup (sh.rustup.rs / static.rust-lang.org / rsproxy.cn)."
      exit 1
    fi
    if [ "${KEEP_TOOLCHAIN}" -eq 1 ]; then
      info "Rust toolchain ('cargo') not found — installing minimal stable rustup toolchain for ${TARGET_USER} (kept after install) ..."
      if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
        sudo -u "${TARGET_USER}" sh "${RUSTUP_SH}" -y --profile minimal --default-host "${RUST_HOST_TRIPLE}" </dev/null
      else
        sh "${RUSTUP_SH}" -y --profile minimal --default-host "${RUST_HOST_TRIPLE}" </dev/null
      fi
      if [ -x "${TARGET_HOME}/.cargo/bin/cargo" ]; then
        CARGO_BIN="${TARGET_HOME}/.cargo/bin/cargo"
      elif command -v cargo >/dev/null 2>&1; then
        CARGO_BIN="$(command -v cargo)"
      fi
    else
      USED_EPHEMERAL_RUSTUP=1
      BUILD_RUSTUP_HOME="${INSTALL_TMP_ROOT}/rustup"
      BUILD_CARGO_HOME="${INSTALL_TMP_ROOT}/cargo"
      mkdir -p "${BUILD_RUSTUP_HOME}" "${BUILD_CARGO_HOME}"
      if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
        chown -R "${TARGET_UID}:${TARGET_GID:-${TARGET_UID}}" "${BUILD_RUSTUP_HOME}" "${BUILD_CARGO_HOME}" 2>/dev/null || chown -R "${TARGET_USER}" "${BUILD_RUSTUP_HOME}" "${BUILD_CARGO_HOME}" 2>/dev/null || true
      fi
      info "Rust toolchain ('cargo') not found — bootstrapping ephemeral minimal toolchain (removed after compilation) ..."
      if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
        sudo -u "${TARGET_USER}" env \
          RUSTUP_HOME="${BUILD_RUSTUP_HOME}" \
          CARGO_HOME="${BUILD_CARGO_HOME}" \
          sh "${RUSTUP_SH}" -y --profile minimal --no-modify-path --default-host "${RUST_HOST_TRIPLE}" </dev/null
      else
        env \
          RUSTUP_HOME="${BUILD_RUSTUP_HOME}" \
          CARGO_HOME="${BUILD_CARGO_HOME}" \
          sh "${RUSTUP_SH}" -y --profile minimal --no-modify-path --default-host "${RUST_HOST_TRIPLE}" </dev/null
      fi
      if [ -x "${BUILD_CARGO_HOME}/bin/cargo" ]; then
        CARGO_BIN="${BUILD_CARGO_HOME}/bin/cargo"
      fi
    fi
  fi

  if [ -n "${CARGO_BIN}" ]; then
    LOCKED_FLAG=""
    if [ -f "${WORK_SRC_DIR}/Cargo.lock" ]; then
      LOCKED_FLAG="--locked"
    fi
    if [ -n "${CALLER_CARGO_TARGET_DIR}" ]; then
      EFFECTIVE_TARGET_DIR="${CALLER_CARGO_TARGET_DIR}"
    else
      EFFECTIVE_TARGET_DIR="${INSTALL_TMP_ROOT}/target"
      mkdir -p "${EFFECTIVE_TARGET_DIR}"
      if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
        chown -R "${TARGET_UID}:${TARGET_GID:-${TARGET_UID}}" "${EFFECTIVE_TARGET_DIR}" 2>/dev/null || chown -R "${TARGET_USER}" "${EFFECTIVE_TARGET_DIR}" 2>/dev/null || true
      fi
    fi

    CARGO_DIR_BIN="$(dirname "${CARGO_BIN}")"
    LAUNCHER_PKG=""
    if [ "${HOST_UNAME}" = "Linux" ]; then
      LAUNCHER_PKG="-p vpngate-launcher"
    fi
    info "Building optimized ${HOST_ARCH} 'vpngate' from Rust workspace (${WORK_SRC_DIR}) ..."
    if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
      # shellcheck disable=SC2086
      sudo -u "${TARGET_USER}" env \
        PATH="${CARGO_DIR_BIN}:${TARGET_HOME}/.cargo/bin:${PATH}" \
        ${BUILD_RUSTUP_HOME:+RUSTUP_HOME="${BUILD_RUSTUP_HOME}"} \
        ${BUILD_CARGO_HOME:+CARGO_HOME="${BUILD_CARGO_HOME}"} \
        "${CARGO_BIN}" build --release ${LOCKED_FLAG} \
        -p vpngate-cli ${LAUNCHER_PKG} \
        --target "${RUST_HOST_TRIPLE}" \
        --manifest-path "${WORK_SRC_DIR}/Cargo.toml" \
        --target-dir "${EFFECTIVE_TARGET_DIR}"
    else
      # shellcheck disable=SC2086
      env \
        PATH="${CARGO_DIR_BIN}:${PATH}" \
        ${BUILD_RUSTUP_HOME:+RUSTUP_HOME="${BUILD_RUSTUP_HOME}"} \
        ${BUILD_CARGO_HOME:+CARGO_HOME="${BUILD_CARGO_HOME}"} \
        "${CARGO_BIN}" build --release ${LOCKED_FLAG} \
        -p vpngate-cli ${LAUNCHER_PKG} \
        --target "${RUST_HOST_TRIPLE}" \
        --manifest-path "${WORK_SRC_DIR}/Cargo.toml" \
        --target-dir "${EFFECTIVE_TARGET_DIR}"
    fi
    BIN_SRC="${EFFECTIVE_TARGET_DIR}/${RUST_HOST_TRIPLE}/release/vpngate"
    LAUNCHER_SRC="${EFFECTIVE_TARGET_DIR}/${RUST_HOST_TRIPLE}/release/vpngate-launcher"
  elif [ -x "${WORK_SRC_DIR}/target/${RUST_HOST_TRIPLE}/release/vpngate" ]; then
    BIN_SRC="${WORK_SRC_DIR}/target/${RUST_HOST_TRIPLE}/release/vpngate"
    if [ -x "${WORK_SRC_DIR}/target/${RUST_HOST_TRIPLE}/release/vpngate-launcher" ]; then
      LAUNCHER_SRC="${WORK_SRC_DIR}/target/${RUST_HOST_TRIPLE}/release/vpngate-launcher"
    fi
  fi
elif [ -x "${WORK_SRC_DIR}/vpngate" ]; then
  BIN_SRC="${WORK_SRC_DIR}/vpngate"
  if [ -x "${WORK_SRC_DIR}/vpngate-launcher" ]; then
    LAUNCHER_SRC="${WORK_SRC_DIR}/vpngate-launcher"
  fi
fi

if [ -z "${BIN_SRC}" ] || [ ! -f "${BIN_SRC}" ]; then
  warn "Could not build or locate 'vpngate' binary."
  exit 1
fi
if command -v file >/dev/null 2>&1; then
  BIN_DESC="$(file -b "${BIN_SRC}" 2>/dev/null || true)"
  BIN_OK=0
  if [ "${HOST_ARCH}" = "aarch64" ]; then
    case "${BIN_DESC}" in
      *ARM\ aarch64*|*AArch64*|*aarch64*|*ARM64*|*arm64*) BIN_OK=1 ;;
    esac
  else
    case "${BIN_DESC}" in
      *x86-64*|*x86_64*|*X86-64*|*AMD64*|*amd64*) BIN_OK=1 ;;
    esac
  fi
  if [ "${BIN_OK}" -ne 1 ]; then
    echo "[-] Refusing binary that does not match host ISA ${HOST_ARCH}: ${BIN_SRC}" >&2
    echo "    ${BIN_DESC}" >&2
    exit 1
  fi
fi

# Prevent boot-time L2TP/IPsec daemons from holding UDP 500, 4500, or 1701 on Linux
if [ "${HOST_UNAME}" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
  sudo systemctl disable --now xl2tpd.service </dev/null 2>/dev/null || true
  sudo systemctl disable --now kl2tpd.service </dev/null 2>/dev/null || true
  sudo systemctl disable --now strongswan.service </dev/null 2>/dev/null || true
  sudo systemctl disable --now strongswan-starter.service </dev/null 2>/dev/null || true
  sudo systemctl disable --now ipsec.service </dev/null 2>/dev/null || true
fi

sudo mkdir -p /usr/local/bin
sudo rm -f /usr/local/bin/vpngate
info "Installing native binary to /usr/local/bin/vpngate ..."
sudo install -m 0755 "${BIN_SRC}" /usr/local/bin/vpngate
# Drop a leftover `cargo install` copy so PATH cannot keep serving the old binary.
CARGO_SHADOW="${TARGET_HOME}/.cargo/bin/vpngate"
if [ -e "${CARGO_SHADOW}" ] && [ "${CARGO_SHADOW}" != "/usr/local/bin/vpngate" ]; then
  rm -f "${CARGO_SHADOW}" 2>/dev/null || sudo rm -f "${CARGO_SHADOW}" 2>/dev/null || true
  info "Removed leftover previous binary ${CARGO_SHADOW}"
fi

if [ "${TOOLCHAIN_POLICY}" = "remove" ] && [ -n "${INSTALLED_COMPILE_PKGS}" ]; then
  info "Removing compile-only packages we installed:${INSTALLED_COMPILE_PKGS}"
  # shellcheck disable=SC2086
  if command -v apt-get >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get remove -y ${INSTALLED_COMPILE_PKGS} </dev/null 2>/dev/null || true
    sudo env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y </dev/null 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf remove -y ${INSTALLED_COMPILE_PKGS} </dev/null 2>/dev/null || true
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -R --noconfirm ${INSTALLED_COMPILE_PKGS} </dev/null 2>/dev/null || true
  fi
  ok "Compile-only packages removed. Runtime VPN packages (OpenVPN, xl2tpd, …) were kept."
elif [ "${TOOLCHAIN_POLICY}" = "keep" ]; then
  if [ "${NEED_RUST}" -eq 1 ]; then
    ok "Rust toolchain kept at ${TARGET_HOME}/.cargo (as requested)."
  fi
  if [ -n "${INSTALLED_COMPILE_PKGS}" ]; then
    ok "C linker packages kept:${INSTALLED_COMPILE_PKGS}"
  fi
fi

if [ "${HOST_UNAME}" = "Linux" ] && [ -x "${LAUNCHER_SRC:-}" ]; then
  info "Installing GNOME GTK4/VTE window launcher (/usr/local/bin/vpngate-launcher) ..."
  sudo rm -f /usr/local/bin/vpngate-launcher /usr/local/bin/vpngate-launcher.py
  sudo install -m 0755 "${LAUNCHER_SRC}" /usr/local/bin/vpngate-launcher

  if [ -f "${WORK_SRC_DIR}/vpngate.desktop" ]; then
    info "Installing GNOME Desktop Entry (/usr/share/applications/vpngate.desktop) ..."
    sudo mkdir -p /usr/share/applications
    install_lf_file "${WORK_SRC_DIR}/vpngate.desktop" /usr/share/applications/vpngate.desktop 0644
    if command -v update-desktop-database >/dev/null 2>&1; then
      sudo update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
  fi
fi

if [ "${HOST_UNAME}" = "Linux" ]; then
  ICON_ROOT="${WORK_SRC_DIR}/assets"
  if [ -f "${ICON_ROOT}/vpngate.svg" ]; then
    info "Installing VPN Gate Connect app icon ..."
    sudo mkdir -p /usr/share/icons/hicolor/scalable/apps
    sudo install -m 0644 "${ICON_ROOT}/vpngate.svg" /usr/share/icons/hicolor/scalable/apps/vpngate.svg
    for sz in 16 24 32 48 64 128 256 512; do
      png="${ICON_ROOT}/icons/hicolor/${sz}x${sz}/apps/vpngate.png"
      if [ -f "${png}" ]; then
        sudo mkdir -p "/usr/share/icons/hicolor/${sz}x${sz}/apps"
        sudo install -m 0644 "${png}" "/usr/share/icons/hicolor/${sz}x${sz}/apps/vpngate.png"
      fi
    done
    if [ -f "${ICON_ROOT}/vpngate-256.png" ]; then
      sudo mkdir -p /usr/share/pixmaps
      sudo install -m 0644 "${ICON_ROOT}/vpngate-256.png" /usr/share/pixmaps/vpngate.png
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
      sudo gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
    elif command -v update-icon-caches >/dev/null 2>&1; then
      sudo update-icon-caches /usr/share/icons/hicolor >/dev/null 2>&1 || true
    fi
  fi
fi

# 3. Post-install cleanup & host environment cleanliness verification
cleanup_install_tmp
if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
  if [ -d "${USER_CACHE_DIR}" ] && [ -n "${TARGET_UID}" ]; then
    chown -R "${TARGET_UID}:${TARGET_GID:-${TARGET_UID}}" "${USER_CACHE_DIR}" 2>/dev/null || chown -R "${TARGET_USER}" "${USER_CACHE_DIR}" 2>/dev/null || true
  fi
  rmdir /root/.cache/vpngate 2>/dev/null || true
fi

POST_CLEAN_ISSUES=""
if [ -n "${INSTALL_TMP_ROOT}" ] && [ -e "${INSTALL_TMP_ROOT}" ]; then
  POST_CLEAN_ISSUES="${POST_CLEAN_ISSUES} ${INSTALL_TMP_ROOT}"
fi
if [ "${HAD_LOCAL_TARGET}" -eq 0 ] && [ -z "${CALLER_CARGO_TARGET_DIR}" ] && [ -e "${SCRIPT_DIR}/target" ]; then
  POST_CLEAN_ISSUES="${POST_CLEAN_ISSUES} ${SCRIPT_DIR}/target"
fi
if [ "${HAD_EXISTING_CARGO}" -eq 0 ] && [ "${USED_EPHEMERAL_RUSTUP}" -eq 1 ]; then
  for eph_dir in "${TARGET_HOME}/.rustup" "${TARGET_HOME}/.cargo"; do
    if [ -e "${eph_dir}" ]; then
      POST_CLEAN_ISSUES="${POST_CLEAN_ISSUES} ${eph_dir}"
    fi
  done
fi

if [ -z "${POST_CLEAN_ISSUES}" ]; then
  ok "Post-install cleanup verified: temporary build & staging artifacts removed (host environment clean)."
else
  warn "Post-install check noticed leftover temporary path(s):${POST_CLEAN_ISSUES}"
fi

echo ""
ok "Installation complete! Running 'vpngate doctor' readiness check:"
sudo env VPNGATE_CACHE_DIR="${USER_CACHE_DIR}" /usr/local/bin/vpngate doctor --no-resize || true
echo ""
ok "Launch interactive console anytime with:  vpngate"
if [ "${HOST_UNAME}" = "Linux" ]; then
  ok "Or launch dark GNOME GTK/VTE window with: vpngate -w"
fi
}

main "$@"
