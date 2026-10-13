#!/usr/bin/env bash
# TRANCE examiner-workstation hardening (Linux). Run it yourself, once, as root:
#
#     sudo bash scripts/examiner-setup.sh            # asks before changing anything
#     sudo bash scripts/examiner-setup.sh --yes      # no questions
#     sudo bash scripts/examiner-setup.sh --dry-run  # only print what it would do
#
# What it does
#   1. Turns off GNOME's automount/autorun for removable media, system-wide and locked
#      (dconf), so plugging in an evidence drive from a possibly compromised machine does
#      not mount it, open a file manager on it, or offer to run anything from it.
#   2. Installs USBGuard, writes an allow-list of the USB devices plugged in *right now*
#      (keyboard, mouse, ...) and starts it, so any other USB device is blocked until you
#      allow it on purpose.
#
# Safety: it never overwrites or deletes an existing file. A config file that already exists
# with different content is left alone and you are told what to change by hand.
#
# BEFORE RUNNING: unplug every USB drive (evidence AND tools drive). Whatever is plugged in
# when the allow-list is generated is allowed from then on.

set -euo pipefail

ASSUME_YES=0
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --yes | -y) ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,21p' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

DCONF_PROFILE=/etc/dconf/profile/user
DCONF_DB_DIR=/etc/dconf/db/local.d
DCONF_KEYFILE=$DCONF_DB_DIR/00-trance-media-handling
DCONF_LOCKFILE=$DCONF_DB_DIR/locks/00-trance-media-handling
USBGUARD_RULES=/etc/usbguard/rules.conf
USBGUARD_CONF=/etc/usbguard/usbguard-daemon.conf

say() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    would run: %s\n' "$*"
    else
        "$@"
    fi
}

# Create $1 with content $2 (mode $3). Never overwrites: an identical existing file is fine,
# a different one is left untouched and reported.
write_new_file() {
    local path=$1 content=$2 mode=${3:-0644}
    if [ -e "$path" ]; then
        if [ "$(cat "$path")" = "$content" ]; then
            say "$path already set up"
        else
            warn "$path already exists with other content -- left unchanged. Wanted:"
            printf '%s\n' "$content" | sed 's/^/        /' >&2
        fi
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    would create %s:\n' "$path"
        printf '%s\n' "$content" | sed 's/^/        /'
        return 0
    fi
    mkdir -p "$(dirname "$path")"
    (umask 077 && printf '%s\n' "$content" >"$path")
    chmod "$mode" "$path"
    say "created $path"
}

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    warn "run this with sudo: sudo bash $0"
    exit 1
fi

cat <<'EOF'
TRANCE examiner setup
  - GNOME: removable-media automount and autorun off (system-wide, locked)
  - USBGuard: only the USB devices plugged in right now stay allowed

Unplug every USB drive now (evidence and tools drives). Keep only keyboard/mouse.
EOF
if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    read -r -p "Continue? [y/N] " answer
    case "$answer" in
        y | Y | yes | YES) ;;
        *)
            echo "nothing changed."
            exit 0
            ;;
    esac
fi

# --- 1. GNOME automount -----------------------------------------------------------------
if command -v dconf >/dev/null 2>&1; then
    if [ -e "$DCONF_PROFILE" ] && ! grep -qx 'system-db:local' "$DCONF_PROFILE"; then
        warn "$DCONF_PROFILE exists without 'system-db:local' -- add that line by hand,"
        warn "otherwise the settings below are not applied."
    else
        write_new_file "$DCONF_PROFILE" "$(printf 'user-db:user\nsystem-db:local')"
    fi
    write_new_file "$DCONF_KEYFILE" "$(
        cat <<'EOF'
# TRANCE: never mount, open or run anything from removable media automatically.
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF
    )"
    write_new_file "$DCONF_LOCKFILE" "$(
        cat <<'EOF'
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
EOF
    )"
    run dconf update
    say "GNOME automount off -- log out and back in for it to take effect."
else
    warn "dconf not found (not a GNOME desktop?) -- automount step skipped. Turn off"
    warn "automounting in your desktop's own settings instead."
fi

# --- 2. USBGuard ------------------------------------------------------------------------
if ! command -v usbguard >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        run apt-get install -y usbguard
    elif command -v dnf >/dev/null 2>&1; then
        run dnf install -y usbguard
    elif command -v zypper >/dev/null 2>&1; then
        run zypper --non-interactive install usbguard
    elif command -v pacman >/dev/null 2>&1; then
        run pacman -S --noconfirm usbguard
    elif [ "$DRY_RUN" -eq 1 ]; then
        printf '    would install usbguard (no known package manager found)\n'
    else
        warn "no known package manager; install usbguard yourself and run this again."
        exit 1
    fi
fi

if [ -s "$USBGUARD_RULES" ]; then
    say "$USBGUARD_RULES already has rules -- left unchanged."
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '    would write: usbguard generate-policy > %s (mode 0600)\n' "$USBGUARD_RULES"
else
    if [ -e "$USBGUARD_RULES" ] && [ ! -s "$USBGUARD_RULES" ]; then
        say "$USBGUARD_RULES is empty; filling it."
    fi
    policy=$(mktemp)
    usbguard generate-policy >"$policy"
    if [ ! -s "$policy" ]; then
        rm -f "$policy"
        warn "usbguard generate-policy produced nothing; not enabling USBGuard (it would"
        warn "block the keyboard). Check 'lsusb' and run again."
        exit 1
    fi
    mkdir -p "$(dirname "$USBGUARD_RULES")"
    install -m 0600 "$policy" "$USBGUARD_RULES"
    rm -f "$policy"
    say "allow-list written: $(grep -c '^allow' "$USBGUARD_RULES") device(s) currently plugged in."
fi

# The shipped defaults are already what TRANCE wants; check, never edit.
if [ -r "$USBGUARD_CONF" ]; then
    for want in ImplicitPolicyTarget=block PresentDevicePolicy=apply-policy \
        InsertedDevicePolicy=apply-policy; do
        key=${want%%=*}
        have=$(grep -E "^${key}=" "$USBGUARD_CONF" | tail -n 1 || true)
        if [ "$have" != "$want" ]; then
            warn "$USBGUARD_CONF has '${have:-$key unset}', recommended '$want' (edit by hand)."
        fi
    done
fi

if [ "$DRY_RUN" -eq 1 ] || [ -s "$USBGUARD_RULES" ]; then
    run systemctl enable --now usbguard
else
    warn "no USBGuard rules in place; not starting it."
fi

cat <<'EOF'

Done. When you need an evidence or tools drive:
  sudo usbguard list-devices --blocked        # find its number
  sudo usbguard allow-device <number>         # until it is unplugged (not permanent)
In TRANCE use "Import from drive..." (copies, verifies hashes, makes the copy read-only),
then unplug the drive. To mount by hand, mount read-only: udisksctl mount -b /dev/sdX1 -o ro,noatime
EOF
