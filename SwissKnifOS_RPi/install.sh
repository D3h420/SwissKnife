#!/usr/bin/env bash
# Install the current SwissKnife clone as the Raspberry Pi application.
set -Eeuo pipefail

SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARGET=/opt/SwissKnife
DATA=/var/lib/swissknife
UNIT=/etc/systemd/system/swissknifos.service
SERVICE=swissknifos.service

usage() {
    cat <<'EOF'
Usage: sudo bash SwissKnifOS_RPi/install.sh [OPTION]

No option                   Install or repair SwissKnifOS
--install-network-manager   Also install NetworkManager if it is absent
--with-optional-tools       Also install optional bully and build tools
--disable-autostart         Stop and disable the LCD service
--uninstall-service         Remove only the LCD service; keep code and data
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "Run with sudo."
[[ $# -le 1 ]] || { usage; exit 2; }

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --disable-autostart)
        systemctl disable --now "$SERVICE"
        echo "Autostart disabled. Code and data remain in place."
        exit 0 ;;
    --uninstall-service)
        systemctl disable --now "$SERVICE" 2>/dev/null || true
        rm -f -- "$UNIT"
        systemctl daemon-reload
        echo "Service removed. Code and data remain in place."
        exit 0 ;;
    ""|--install-network-manager|--with-optional-tools) ;;
    *) usage; exit 2 ;;
esac

[[ -f /etc/os-release ]] || die "Cannot identify the operating system."
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == raspbian || ${ID:-} == debian ]] || die "Raspberry Pi OS (Debian based) is required."
[[ -r /proc/device-tree/model ]] || die "This does not appear to be a Raspberry Pi."
model="$(tr -d '\0' </proc/device-tree/model)"
[[ $model == *"Raspberry Pi Zero 2 W"* ]] || die "Tested hardware is Raspberry Pi Zero 2 W; detected: $model"
[[ -f "$SOURCE/SwissKnifOS_RPi/app.py" && -d "$SOURCE/.git" ]] || die "Run this script from a complete Git clone."
command -v git >/dev/null || die "Git is required."
command -v apt-get >/dev/null || die "apt-get is required."
command -v systemctl >/dev/null || die "systemd is required."
if [[ ! -e "$TARGET" && -n "$(git -c "safe.directory=$SOURCE" -C "$SOURCE" status --porcelain)" ]]; then
    die "The source clone has uncommitted changes. Commit them first; the installer clones committed Git content."
fi

printf 'Source: %s\nInstalled clone: %s\nPersistent data: %s\n' "$SOURCE" "$TARGET" "$DATA"
printf 'Hardware: %s\n' "$model"
echo "The installer enables SPI and installs LCD and core module packages."
echo "It does not change Wi-Fi profiles, interface roles, or DHCP configuration."

packages=(
    python3-pil python3-spidev python3-lgpio python3-scapy fonts-dejavu-core
    aircrack-ng iproute2 ethtool arp-scan hostapd dnsmasq iptables
    iw iputils-ping usbutils rfkill wireless-tools mdk4
)
if [[ ${1:-} == --install-network-manager ]]; then
    packages+=(network-manager)
fi
if [[ ${1:-} == --with-optional-tools ]]; then
    packages+=(bully git autoconf automake libtool shtool libssl-dev pkg-config build-essential)
fi

apt-get update
apt-get install -y "${packages[@]}"

if ! command -v nmcli >/dev/null; then
    echo "NetworkManager is absent. Pi Commands Wi-Fi actions need it."
    echo "Install explicitly with: sudo bash SwissKnifOS_RPi/install.sh --install-network-manager"
fi

if [[ ! -e /dev/spidev0.0 ]]; then
    command -v raspi-config >/dev/null || die "Install raspi-config and enable SPI, then rerun this script."
    raspi-config nonint do_spi 0
    echo "SPI enabled in boot configuration. Reboot after installation to expose /dev/spidev0.0."
fi
spi_reboot_required=0
[[ -e /dev/spidev0.0 ]] || spi_reboot_required=1

mkdir -p -- "$DATA/log" "$DATA/tools"
chmod 700 "$DATA" "$DATA/log" "$DATA/tools"

if [[ ! -e "$TARGET" ]]; then
    origin="$(git -c "safe.directory=$SOURCE" -C "$SOURCE" remote get-url origin)" || die "Source clone needs an origin remote."
    [[ -n "$origin" ]] || die "Source clone needs an origin remote."
    stage="$(mktemp -d /opt/.SwissKnife.install.XXXXXX)"
    trap 'rm -rf -- "$stage"' EXIT
    rmdir "$stage"
    git -c "safe.directory=$SOURCE" clone --local --no-hardlinks "$SOURCE" "$stage"
    git -C "$stage" remote set-url origin "$origin"
    mv -- "$stage" "$TARGET"
    trap - EXIT
    echo "Created Git clone in $TARGET (origin: $origin)."
elif [[ ! -d "$TARGET/.git" ]]; then
    die "$TARGET exists but is not a Git clone. Move it aside manually before installing."
else
    source_origin="$(git -c "safe.directory=$SOURCE" -C "$SOURCE" remote get-url origin 2>/dev/null || true)"
    target_origin="$(git -c "safe.directory=$TARGET" -C "$TARGET" remote get-url origin 2>/dev/null || true)"
    [[ -z "$source_origin" || "$source_origin" == "$target_origin" ]] || die "$TARGET points to a different Git origin."
    if [[ "$SOURCE" != "$TARGET" ]]; then
        source_branch="$(git -c "safe.directory=$SOURCE" -C "$SOURCE" branch --show-current)"
        target_branch="$(git -c "safe.directory=$TARGET" -C "$TARGET" branch --show-current)"
        [[ -n "$source_branch" && "$source_branch" == "$target_branch" ]] || die "Source and installed clone must be on the same branch."
        [[ -z "$(git -c "safe.directory=$TARGET" -C "$TARGET" status --porcelain --untracked-files=no)" ]] || die "$TARGET has local changes; commit or resolve them before updating."
        if ! git -c "safe.directory=$SOURCE" -c "safe.directory=$TARGET" -C "$TARGET" fetch "$SOURCE" "$source_branch" ||
           ! git -c "safe.directory=$TARGET" -C "$TARGET" merge --ff-only FETCH_HEAD; then
            chown -R "${SUDO_UID:-$(stat -c %u "$SOURCE")}:${SUDO_GID:-$(stat -c %g "$SOURCE")}" "$TARGET"
            die "Could not fast-forward the installed clone from the source clone."
        fi
        echo "Updated $TARGET from $SOURCE."
    else
        echo "Existing installed clone preserved. Use git pull here for code updates."
    fi
fi

# Migrate data from older installations without removing their originals.
if [[ -d "$TARGET/log" ]]; then cp -an -- "$TARGET/log/." "$DATA/log/"; fi
if [[ -d "$TARGET/tools" ]]; then cp -an -- "$TARGET/tools/." "$DATA/tools/"; fi
chmod 700 "$DATA" "$DATA/log" "$DATA/tools"

# A non-root operator can run ordinary git pull in the installed clone.
owner_uid="${SUDO_UID:-$(stat -c %u "$SOURCE")}"
owner_gid="${SUDO_GID:-$(stat -c %g "$SOURCE")}"
chown -R "$owner_uid:$owner_gid" "$TARGET"
if [[ -d "$TARGET/log" ]]; then
    chown -R root:root "$TARGET/log"
    chmod 700 "$TARGET/log"
fi

install -m 0644 "$TARGET/SwissKnifOS_RPi/swissknifos.service" "$UNIT"
systemctl daemon-reload
systemctl enable "$SERVICE"
if [[ $spi_reboot_required -eq 1 ]]; then
    echo "Installation complete. Reboot now; the enabled LCD service will start after reboot."
    exit 0
fi
systemctl restart "$SERVICE"
sleep 2

if systemctl is-active --quiet "$SERVICE"; then
    echo "SwissKnifOS is running. Update later with: cd $TARGET && git pull"
    echo "The LCD application restarts itself when idle after a new Git revision is pulled."
    if [[ ! -e /dev/spidev0.0 ]]; then echo "Reboot is still required for SPI."; fi
else
    echo "Service did not stay active. Check: journalctl -u $SERVICE -b"
    exit 1
fi
