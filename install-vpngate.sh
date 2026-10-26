#!/bin/sh
# install-vpngate.sh — One-step Linux & macOS Desktop Installer, Residue Cleaner & Uninstaller for `vpngate` (Rust Edition)
# POSIX /bin/sh (dash, sh, bash, zsh) compatible — works via `sh ./install-vpngate.sh`
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
REPO_SLUG="${VPNGATE_REPO:-warmaster726/vpngate-connect}"
HOST_UNAME="$(uname -s 2>/dev/null || echo Linux)"

show_help() {
  cat <<'EOF'
Usage: sh ./install-vpngate.sh [OPTIONS]
   or: ./install-vpngate.sh [OPTIONS]

Installs, upgrades, or removes the single-binary Rust VPN Gate Desktop Suite
on Linux (Kali, Debian, Ubuntu, Mint, Pop!_OS, Fedora, Arch) and macOS,
automatically cleaning residues from previous Python or Rust installations.

Options:
  (no arguments)       Clean legacy residues, install OS packages, build/install `vpngate`, and run `doctor`
  --uninstall, -u      Disconnect active VPNs, remove binaries/launchers/caches, and verify zero residues
  --purge-packages     With --uninstall on Linux, also purge dedicated L2TP helper package (xl2tpd)
  --skip-apt           Skip system package installation step (alias: --skip-deps)
  --repo <owner/repo>  GitHub repository slug when downloading release artifacts outside a local checkout
  --help, -h           Show this help message and exit
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

if [ "${HOST_UNAME}" = "Darwin" ]; then
  USER_CACHE_DIR="${TARGET_HOME}/Library/Caches/vpngate"
else
  USER_CACHE_DIR="${TARGET_HOME}/.cache/vpngate"
fi

NL='
'
CLEANED_COUNT=0
CLEANED_LIST=""

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
  tmp_stage="$(mktemp "/tmp/vpngate-install.XXXXXX")"
  tr -d '\r' < "${src_file}" > "${tmp_stage}"
  sudo install -m "${file_mode}" "${tmp_stage}" "${dst_file}"
  rm -f "${tmp_stage}"
}

cleanup_previous_residues() {
  info "Scanning system for active sessions and residues from previous vpngate installations ..."

  # 1. Gracefully disconnect via installed Rust `vpngate` or legacy Python `vpngate.py`
  for cache_cand in "${USER_CACHE_DIR}" "/root/.cache/vpngate"; do
    sudo test -d "${cache_cand}" || continue
    if sudo test -f "${cache_cand}/active_state.json" ||
       sudo test -f "${cache_cand}/openvpn.pid" ||
       sudo test -f "${cache_cand}/monitor.pid" ||
       sudo test -d "/run/vpngate-l2tp"; then
      if [ -x /usr/local/bin/vpngate ] && [ ! -L /usr/local/bin/vpngate ]; then
        sudo env VPNGATE_CACHE_DIR="${cache_cand}" /usr/local/bin/vpngate disconnect --no-resize >/dev/null 2>&1 || true
        record_cleaned "Disconnected active/stale Rust vpngate session (${cache_cand})"
      elif [ -f /usr/local/bin/vpngate.py ] && command -v python3 >/dev/null 2>&1; then
        sudo env PYTHONDONTWRITEBYTECODE=1 VPNGATE_CACHE_DIR="${cache_cand}" python3 -B /usr/local/bin/vpngate.py disconnect --no-resize >/dev/null 2>&1 || true
        record_cleaned "Disconnected legacy Python vpngate.py session (${cache_cand})"
      fi
    fi
  done

  # 2. Terminate orphaned background daemons (_monitor, _ikev1, vpngate-launcher, openvpn, xl2tpd, pppd) on Linux
  if [ -d /proc ] && command -v python3 >/dev/null 2>&1; then
    vg_killed_procs="$(sudo python3 - "$$" "${PPID:-0}" <<'PY' || true
import os, signal, sys, time

ignore = {os.getpid(), os.getppid()}
for a in sys.argv[1:]:
    if a.isdigit():
        ignore.add(int(a))

targets = []
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    pid = int(entry)
    if pid in ignore:
        continue
    try:
        raw = open(f"/proc/{pid}/cmdline", "rb").read()
    except Exception:
        continue
    argv = [p.decode("utf-8", "ignore") for p in raw.split(b"\x00") if p]
    if not argv:
        continue
    joined = " ".join(argv)
    if "install-vpngate" in joined:
        continue
    exe_base = os.path.basename(argv[0])
    hit = None
    if any("vpngate-launcher" in a for a in argv):
        hit = f"vpngate-launcher(pid={pid})"
    elif any("vpngate" in os.path.basename(a) for a in argv) and any(a in ("_monitor", "_ikev1") for a in argv):
        hit = f"vpngate-daemon(pid={pid})"
    elif exe_base == "openvpn" and ("vpngate-" in joined or "/vpngate/" in joined):
        hit = f"openvpn(pid={pid})"
    elif exe_base in ("xl2tpd", "pppd") and "/run/vpngate-l2tp" in joined:
        hit = f"{exe_base}(pid={pid})"
    if hit:
        targets.append((pid, hit))

for pid, _ in targets:
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
if targets:
    time.sleep(0.35)
    for pid, _ in targets:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    print(", ".join(lbl for _, lbl in targets))
PY
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
BOOTSTRAP_TMP_DIR=""
cleanup_bootstrap_tmp() {
  if [ -n "${BOOTSTRAP_TMP_DIR}" ] && [ -d "${BOOTSTRAP_TMP_DIR}" ]; then
    rm -rf "${BOOTSTRAP_TMP_DIR}"
  fi
}
trap cleanup_bootstrap_tmp EXIT INT TERM

cleanup_previous_residues
if [ "${CLEANED_COUNT}" -gt 0 ]; then
  ok "Pre-install cleanup resolved ${CLEANED_COUNT} residue(s):"
  printf '%s\n' "${CLEANED_LIST}"
else
  ok "Pre-install check clean: no legacy residues detected."
fi

# 1. Install OS tunnel & GNOME window dependencies
if [ "${SKIP_DEPS}" -eq 0 ]; then
  if [ "${HOST_UNAME}" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      info "Ensuring OpenVPN is installed via Homebrew ..."
      sudo -u "${TARGET_USER}" brew list openvpn >/dev/null 2>&1 || sudo -u "${TARGET_USER}" brew install openvpn
    fi
  elif command -v apt-get >/dev/null 2>&1; then
    info "Installing required OpenVPN & L2TP/PPP packages via apt-get ..."
    sudo apt-get update -qq </dev/null
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      openvpn \
      xl2tpd \
      ppp \
      iproute2 \
      curl </dev/null
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      python3 \
      python3-gi \
      gir1.2-gtk-3.0 \
      gir1.2-vte-2.91 \
      network-manager-openvpn \
      network-manager-openvpn-gnome \
      libnotify-bin </dev/null 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    info "Installing required OpenVPN & L2TP/PPP packages via dnf ..."
    sudo dnf install -y openvpn xl2tpd ppp iproute curl python3 </dev/null
    sudo dnf install -y NetworkManager-openvpn NetworkManager-openvpn-gnome libnotify python3-gobject gtk3 vte291 </dev/null 2>/dev/null || true
  elif command -v pacman >/dev/null 2>&1; then
    info "Installing required OpenVPN & L2TP/PPP packages via pacman ..."
    sudo pacman -Sy --needed --noconfirm openvpn xl2tpd ppp iproute2 curl python </dev/null
    sudo pacman -S --needed --noconfirm networkmanager-openvpn libnotify python-gobject gtk3 vte3 </dev/null 2>/dev/null || true
  fi
fi

# 2. Locate local workspace / prebuilt binary, or fetch `main` source archive from GitHub (Release-free!)
WORK_SRC_DIR="${SCRIPT_DIR}"
BIN_SRC=""

if [ ! -f "${WORK_SRC_DIR}/Cargo.toml" ] && [ ! -x "${WORK_SRC_DIR}/vpngate" ]; then
  BRANCH_NAME="${VPNGATE_BRANCH:-main}"
  BOOTSTRAP_TMP_DIR="$(mktemp -d "/tmp/vpngate-src.XXXXXX")"
  if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
    chown "${TARGET_USER}" "${BOOTSTRAP_TMP_DIR}" 2>/dev/null || true
  fi
  ARCHIVE_URL="https://codeload.github.com/${REPO_SLUG}/tar.gz/refs/heads/${BRANCH_NAME}"
  info "Fetching source archive from ${ARCHIVE_URL} ..."
  curl -fsSL "${ARCHIVE_URL}" -o "${BOOTSTRAP_TMP_DIR}/src.tar.gz" </dev/null
  tar -xzf "${BOOTSTRAP_TMP_DIR}/src.tar.gz" -C "${BOOTSTRAP_TMP_DIR}"
  EXTRACTED_DIR="$(find "${BOOTSTRAP_TMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [ -z "${EXTRACTED_DIR}" ] || [ ! -f "${EXTRACTED_DIR}/Cargo.toml" ]; then
    warn "Downloaded source archive did not contain Cargo.toml."
    exit 1
  fi
  if [ "$(id -u)" -eq 0 ] && [ -n "${TARGET_UID}" ]; then
    chown -R "${TARGET_USER}" "${EXTRACTED_DIR}" 2>/dev/null || true
  fi
  WORK_SRC_DIR="${EXTRACTED_DIR}"
fi

if [ -f "${WORK_SRC_DIR}/Cargo.toml" ]; then
  CARGO_BIN=""
  if [ -x "${TARGET_HOME}/.cargo/bin/cargo" ]; then
    CARGO_BIN="${TARGET_HOME}/.cargo/bin/cargo"
  elif command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
  fi

  if [ -z "${CARGO_BIN}" ]; then
    info "Rust toolchain ('cargo') not found — installing minimal stable rustup toolchain for ${TARGET_USER} ..."
    if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
      sudo -u "${TARGET_USER}" sh -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal' </dev/null
    else
      sh -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal' </dev/null
    fi
    if [ -x "${TARGET_HOME}/.cargo/bin/cargo" ]; then
      CARGO_BIN="${TARGET_HOME}/.cargo/bin/cargo"
    elif command -v cargo >/dev/null 2>&1; then
      CARGO_BIN="$(command -v cargo)"
    fi
  fi

  if [ -n "${CARGO_BIN}" ]; then
    info "Building optimized single-binary 'vpngate' from Rust workspace (${WORK_SRC_DIR}) ..."
    if [ "$(id -u)" -eq 0 ] && [ "${TARGET_USER}" != "root" ]; then
      sudo -u "${TARGET_USER}" env PATH="${TARGET_HOME}/.cargo/bin:${PATH}" "${CARGO_BIN}" build --release -p vpngate-cli --manifest-path "${WORK_SRC_DIR}/Cargo.toml"
    else
      "${CARGO_BIN}" build --release -p vpngate-cli --manifest-path "${WORK_SRC_DIR}/Cargo.toml"
    fi
    BIN_SRC="${WORK_SRC_DIR}/target/release/vpngate"
  elif [ -x "${WORK_SRC_DIR}/target/release/vpngate" ]; then
    BIN_SRC="${WORK_SRC_DIR}/target/release/vpngate"
  fi
elif [ -x "${WORK_SRC_DIR}/vpngate" ]; then
  BIN_SRC="${WORK_SRC_DIR}/vpngate"
fi

if [ -z "${BIN_SRC}" ] || [ ! -f "${BIN_SRC}" ]; then
  warn "Could not build or locate 'vpngate' binary."
  exit 1
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

if [ "${HOST_UNAME}" = "Linux" ] && [ -f "${WORK_SRC_DIR}/vpngate-launcher.py" ]; then
  info "Installing GNOME GTK/VTE window launcher (/usr/local/bin/vpngate-launcher) ..."
  install_lf_file "${WORK_SRC_DIR}/vpngate-launcher.py" /usr/local/bin/vpngate-launcher.py 0755
  sudo ln -sf /usr/local/bin/vpngate-launcher.py /usr/local/bin/vpngate-launcher

  if [ -f "${WORK_SRC_DIR}/vpngate.desktop" ]; then
    info "Installing GNOME Desktop Entry (/usr/share/applications/vpngate.desktop) ..."
    sudo mkdir -p /usr/share/applications
    install_lf_file "${WORK_SRC_DIR}/vpngate.desktop" /usr/share/applications/vpngate.desktop 0644
    if command -v update-desktop-database >/dev/null 2>&1; then
      sudo update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
  fi
fi

echo ""
ok "Installation complete! Running 'vpngate doctor' readiness check:"
/usr/local/bin/vpngate doctor --no-resize || true
echo ""
ok "Launch interactive console anytime with:  vpngate"
if [ "${HOST_UNAME}" = "Linux" ]; then
  ok "Or launch dark GNOME GTK/VTE window with: vpngate -w"
fi
}

main "$@"
