#!/bin/sh
# Build a single-file, self-extracting Linux installer from a Qt-deployed AppDir.
set -eu

usage() {
  cat <<'EOF'
Usage: create-run-installer.sh <AppDir> <output.run>

The generated .run file contains the installer runtime and its Qt libraries.
When launched, it invokes the embedded installer to download the Rust source,
build/install the VPN Gate client, and remove any temporary Rust toolchain.
EOF
}

if [ "$#" -ne 2 ]; then
  usage >&2
  exit 2
fi

appdir=$1
output=$2
if [ ! -d "$appdir" ] || [ ! -x "$appdir/AppRun" ]; then
  echo "[error] AppDir must contain an executable AppRun: $appdir" >&2
  exit 1
fi

output_dir=$(dirname -- "$output")
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd -P)
output="$output_dir/$(basename -- "$output")"
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/vpngate-run-build.XXXXXX")
cleanup() {
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

payload="$temp_dir/payload.tar.gz"
tar -czf "$payload" -C "$appdir" .

cat > "$temp_dir/stub" <<'STUB'
#!/bin/sh
# Self-extracting VPN Gate Connect installer. The compressed AppDir follows the marker.
set -u

usage() {
  cat <<'EOF'
VPN Gate Connect Linux installer

Usage: sh ./vpngate-installer-linux-x64.run [install|uninstall|verify] [options]

With no action, installs the client. The installer downloads the Rust source,
builds and installs it, reuses any existing Rust toolchain, and removes a
Rust toolchain it bootstrapped temporarily. The same file can uninstall it:

  sh ./vpngate-installer-linux-x64.run uninstall
  sh ./vpngate-installer-linux-x64.run --dry-run

Pass --repo, --branch, --skip-deps, or other vpngate-installer CLI options after
the action. System installation may request sudo.
EOF
}

if [ "${1-}" = "--help" ] || [ "${1-}" = "-h" ]; then
  usage
  exit 0
fi

case "$0" in
  /*) script_path=$0 ;;
  */*) script_path=$(pwd -P)/$0 ;;
  *)
    if [ -f "$0" ]; then
      script_path=$(pwd -P)/$0
    else
      script_path=$(command -v "$0") || { echo "[error] Could not locate this installer file." >&2; exit 1; }
    fi
    ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd -P) || exit 1
script_path=$script_dir/$(basename -- "$script_path")
marker='__VPNGATE_RUN_PAYLOAD_V1__'
payload_line=$(awk -v marker="$marker" '$0 == marker { print NR + 1; exit }' "$script_path")
if [ -z "$payload_line" ]; then
  echo "[error] Embedded installer payload marker is missing." >&2
  exit 1
fi

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/vpngate-connect-installer.XXXXXX") || {
  echo "[error] Could not create temporary extraction storage." >&2
  exit 1
}
cleanup() {
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! tail -n "+$payload_line" "$script_path" | tar -xz -C "$temp_dir"; then
  echo "[error] Could not extract the embedded installer runtime." >&2
  exit 1
fi
if [ ! -x "$temp_dir/AppRun" ]; then
  echo "[error] The embedded installer runtime is incomplete." >&2
  exit 1
fi

case "${1-}" in
  install|uninstall|verify|--uninstall|-u|--remove|-uninstall)
    action=$1
    shift
    ;;
  *)
    action=install
    ;;
esac

# Force the full source-download workflow and temporary-toolchain policy after
# user-supplied options, while still permitting branch/repository overrides.
if "$temp_dir/AppRun" "$action" "$@" --system --yes --remove-toolchain; then
  exit 0
else
  status=$?
  echo "[error] VPN Gate Connect installer failed with exit code $status." >&2
  exit "$status"
fi
STUB

marker='__VPNGATE_RUN_PAYLOAD_V1__'
{
  cat "$temp_dir/stub"
  printf '%s\n' "$marker"
  cat "$payload"
} > "$output"
chmod 0755 "$output"

# Refuse to ship an incomplete self-extractor.
if ! "$output" --help >/dev/null; then
  echo "[error] Generated .run file failed its help smoke test." >&2
  exit 1
fi

printf '[ok] Created single-file Linux installer: %s\n' "$output"
