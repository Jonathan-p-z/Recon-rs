#!/usr/bin/env bash
# Installs recon-rs as systemd --user template units (recon-rs@.service /
# recon-rs@.timer) for the CURRENT (non-root) user, one instance per scan target.
#
# Usage: ./deploy/install.sh
#
# Never run this with sudo / as root: this installs systemd *user* units, which must
# be owned by the non-root account that will actually run them. Running as root would
# install into root's own systemd user session instead of yours, which is almost
# certainly not what you want and defeats the point of using --user units.
#
# What this does, every time it's run:
#   1. Builds recon-cli in release mode and installs it to ~/.local/bin/.
#   2. Copies config/ to ~/.config/recon-rs/config/.
#   3. Installs the recon-rs@.service / recon-rs@.timer TEMPLATE units.
#   4. Bootstraps the known VF Corporation VDP sub-targets (vfc, vans, thenorthface,
#      timberland, vfc-int): creates ~/.config/recon-rs/targets/<name>.env from
#      deploy/recon-rs.env.example (never overwriting one that already exists) and a
#      per-instance schedule drop-in, staggered 4h apart.
#   5. Migrates away from the old single-target recon-rs.service/.timer if still
#      installed from a previous version of this script.
#   6. Enables + starts recon-rs@<name>.timer for every *.env file actually present
#      in ~/.config/recon-rs/targets/ — this step is NOT limited to the 5 names
#      bootstrapped in step 4: add a 6th target's targets/<name>.env and drop-in by
#      hand (see deploy/README.md) and re-running this script will pick it up too.

set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "error: do not run install.sh as root or with sudo." >&2
    echo "       This installs systemd --user units, which run as whatever" >&2
    echo "       unprivileged account enables them — that must be you, not root." >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/recon-rs"
TARGETS_DIR="${CONFIG_DIR}/targets"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"

# name -> "domain|HH:MM:SS", 4h apart. Edit this (or add a target by hand afterwards —
# see deploy/README.md) if VF Corporation VDP's scope changes or you're bootstrapping a
# different program's targets instead.
declare -A VFC_TARGETS=(
    [vfc]="vfc.com|00:00:00"
    [vans]="vans.com|04:00:00"
    [thenorthface]="thenorthface.com|08:00:00"
    [timberland]="timberland.com|12:00:00"
    [vfc-int]="vfc-int.com|16:00:00"
)
VFC_PROGRAM_CONFIG="${CONFIG_DIR}/config/programs/vfc-vdp.toml"

echo "==> Building recon-cli in release mode"
(cd "${REPO_DIR}" && cargo build --release -p recon-cli)

echo "==> Installing binary to ${BIN_DIR}/recon-cli"
mkdir -p "${BIN_DIR}"
install -m 755 "${REPO_DIR}/target/release/recon-cli" "${BIN_DIR}/recon-cli"

echo "==> Installing config to ${CONFIG_DIR}/config"
mkdir -p "${CONFIG_DIR}"
rm -rf "${CONFIG_DIR}/config"
cp -r "${REPO_DIR}/config" "${CONFIG_DIR}/config"
mkdir -p "${CONFIG_DIR}/reports" "${TARGETS_DIR}"

echo "==> Installing systemd user template units to ${SYSTEMD_USER_DIR}"
mkdir -p "${SYSTEMD_USER_DIR}"
cp "${REPO_DIR}/deploy/recon-rs@.service" "${SYSTEMD_USER_DIR}/recon-rs@.service"
cp "${REPO_DIR}/deploy/recon-rs@.timer" "${SYSTEMD_USER_DIR}/recon-rs@.timer"

# --- Migrate away from the old single-target (non-instanced) units, if present ---
if [[ -f "${SYSTEMD_USER_DIR}/recon-rs.timer" ]]; then
    echo "==> Found the old single-target recon-rs.timer — disabling and removing it"
    echo "    (superseded by recon-rs@<target>.timer; your scan history in the"
    echo "    database is untouched)"
    systemctl --user disable --now recon-rs.timer 2>/dev/null || true
    systemctl --user stop recon-rs.service 2>/dev/null || true
    rm -f "${SYSTEMD_USER_DIR}/recon-rs.service" "${SYSTEMD_USER_DIR}/recon-rs.timer"
fi

# --- Bootstrap the known VF Corporation VDP sub-targets ---
for name in "${!VFC_TARGETS[@]}"; do
    IFS='|' read -r domain hour <<< "${VFC_TARGETS[${name}]}"
    env_file="${TARGETS_DIR}/${name}.env"

    if [[ -f "${env_file}" ]]; then
        echo "==> ${env_file} already exists — leaving it untouched"
    else
        echo "==> Creating ${env_file} (TARGET=${domain})"
        sed \
            -e "s#__TARGET__#${domain}#g" \
            -e "s#__PROGRAM_CONFIG__#${VFC_PROGRAM_CONFIG}#g" \
            -e "s#__NAME__#${name}#g" \
            "${REPO_DIR}/deploy/recon-rs.env.example" > "${env_file}"
        chmod 600 "${env_file}"
    fi

    dropin_dir="${SYSTEMD_USER_DIR}/recon-rs@${name}.timer.d"
    dropin_file="${dropin_dir}/schedule.conf"
    if [[ -f "${dropin_file}" ]]; then
        echo "==> ${dropin_file} already exists — leaving it untouched"
    else
        echo "==> Creating ${dropin_file} (OnCalendar=*-*-* ${hour})"
        mkdir -p "${dropin_dir}"
        cat > "${dropin_file}" << EOF
# Per-instance schedule for recon-rs@${name} — see recon-rs@.timer for why the base
# template has no OnCalendar= of its own.
[Timer]
OnCalendar=*-*-* ${hour}
EOF
    fi
done

echo "==> Reloading systemd user units"
systemctl --user daemon-reload

echo "==> Enabling every target found in ${TARGETS_DIR}"
shopt -s nullglob
found_any=0
for env_file in "${TARGETS_DIR}"/*.env; do
    found_any=1
    name="$(basename "${env_file}" .env)"
    echo "    enabling recon-rs@${name}.timer"
    systemctl --user enable --now "recon-rs@${name}.timer"
done
shopt -u nullglob
if [[ "${found_any}" -eq 0 ]]; then
    echo "    (none found — this shouldn't happen right after bootstrapping the VF targets above)"
fi

echo
echo "Installed."
echo
placeholders_left=0
for env_file in "${TARGETS_DIR}"/*.env; do
    if grep -q "CHANGE_ME" "${env_file}" 2>/dev/null; then
        placeholders_left=1
    fi
done
if [[ "${placeholders_left}" -eq 1 ]]; then
    echo "!! At least one targets/*.env still has placeholder values (SEED_FILE/"
    echo "!! DATABASE_URL). Every enabled timer is armed, but a run against a file"
    echo "!! that hasn't been edited will fail cleanly and log why — see"
    echo "!! 'journalctl --user -t recon-rs-<name>' — until you edit it."
    echo
fi
echo "Before this can run real scans, edit each file in:"
echo "  ${TARGETS_DIR}/"
echo "(at minimum: SEED_FILE, and DATABASE_URL — same value in every file)."
echo
echo "And re-read the program's CURRENT scope/rules before you do — see"
echo "deploy/README.md. A stale config here does not mean the program's real rules"
echo "haven't changed since."
echo
echo "Check the schedule:  systemctl --user list-timers 'recon-rs@*'"
echo "Watch logs (1 target): journalctl --user -t recon-rs-vfc -f"
echo "Watch logs (all):     journalctl --user -u 'recon-rs@*.service' -f"
