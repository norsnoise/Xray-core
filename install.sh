#!/usr/bin/env bash
# Install the xray binary built by ./build.sh as a systemd service, using the
# same layout and unit as the official XTLS/Xray-install script:
#
#   /usr/local/bin/xray                   binary
#   /usr/local/etc/xray/config.json       config (never overwritten)
#   /usr/local/share/xray/geo{ip,site}.dat  routing data
#   /var/log/xray/                        log directory
#   /etc/systemd/system/xray.service      service, runs as system user xray
#
# Usage:
#   ./build.sh && sudo ./install.sh     install or upgrade, then (re)start
#   sudo ./install.sh --no-geodata      skip downloading geoip/geosite data
#   sudo ./install.sh --uninstall       remove the service, binary and data
#                                       (keeps config, logs and the xray user)
#
# DESTDIR=/some/root stages the files under that root (for packaging); it
# skips user/ownership changes and all systemctl calls.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

DESTDIR="${DESTDIR:-}"
BIN_PATH=/usr/local/bin/xray
CONFIG_DIR=/usr/local/etc/xray
CONFIG_PATH="${CONFIG_DIR}/config.json"
SHARE_DIR=/usr/local/share/xray
LOG_DIR=/var/log/xray
UNIT_PATH=/etc/systemd/system/xray.service
SERVICE_USER=xray
GEODATA_URL=https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release

geodata=1
action=install
for arg in "$@"; do
	case "${arg}" in
	--no-geodata) geodata=0 ;;
	--uninstall) action=uninstall ;;
	-h | --help)
		sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"
		exit 0
		;;
	*)
		echo "error: unknown option: ${arg} (see --help)" >&2
		exit 1
		;;
	esac
done

info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }
die() {
	echo "error: $*" >&2
	exit 1
}

# systemctl / chown only apply to a live install, not a DESTDIR staging.
live() { [ -z "${DESTDIR}" ]; }

preflight() {
	[ "$(uname -s)" = Linux ] || die "only Linux is supported"
	if live; then
		[ "${EUID}" -eq 0 ] || die "run as root, e.g. sudo $0 $*"
		[ -d /run/systemd/system ] || die "systemd is not running on this system"
	fi
}

uninstall() {
	if live; then
		if systemctl list-unit-files xray.service >/dev/null 2>&1; then
			info "Stopping and disabling xray.service"
			systemctl disable --now xray.service || true
		fi
	fi
	rm -f "${DESTDIR}${UNIT_PATH}" "${DESTDIR}${BIN_PATH}"
	rm -rf "${DESTDIR}${SHARE_DIR}"
	if live; then
		systemctl daemon-reload
	fi
	info "Removed the service, binary and ${SHARE_DIR}"
	echo "Kept ${CONFIG_DIR}, ${LOG_DIR} and the ${SERVICE_USER} user; remove them by hand"
	echo "if no longer needed (rm -r ${CONFIG_DIR} ${LOG_DIR}; userdel ${SERVICE_USER})."
}

# A dedicated system user, so the service shares no files or processes with
# other daemons (as it would running as nobody).
ensure_user() {
	id "${SERVICE_USER}" >/dev/null 2>&1 && return
	info "Creating system user ${SERVICE_USER}"
	useradd --system --user-group --no-create-home --home-dir /nonexistent \
		--shell "$(command -v nologin || echo /bin/false)" "${SERVICE_USER}"
}

fetch() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		return 1
	fi
}

# Downloads geoip.dat / geosite.dat and checks them against the published
# SHA-256 sums. Failure is not fatal: the data is only needed for routing
# rules that use geoip:/geosite:, and existing files are kept.
install_geodata() {
	local tmp name want got
	tmp="$(mktemp -d)"
	trap 'rm -rf "${tmp}"; trap - RETURN' RETURN
	for name in geoip geosite; do
		info "Downloading ${name}.dat"
		if ! fetch "${GEODATA_URL}/${name}.dat" "${tmp}/${name}.dat" ||
			! fetch "${GEODATA_URL}/${name}.dat.sha256sum" "${tmp}/${name}.sha256"; then
			warn "could not download ${name}.dat; keeping any existing copy"
			continue
		fi
		want="$(awk '{print $1}' "${tmp}/${name}.sha256")"
		got="$(sha256sum "${tmp}/${name}.dat" | awk '{print $1}')"
		if [ "${want}" != "${got}" ]; then
			warn "${name}.dat checksum mismatch; keeping any existing copy"
			continue
		fi
		install -m 644 "${tmp}/${name}.dat" "${DESTDIR}${SHARE_DIR}/${name}.dat"
	done
}

write_unit() {
	cat >"${DESTDIR}${UNIT_PATH}" <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=${SERVICE_USER}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${BIN_PATH} run -config ${CONFIG_PATH}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
	chmod 644 "${DESTDIR}${UNIT_PATH}"
}

config_reminder() {
	echo
	if [ "$(tr -d '[:space:]' <"${DESTDIR}${CONFIG_PATH}")" = '{}' ]; then
		echo "NOTE: ${CONFIG_PATH} is still the empty placeholder,"
		echo "      so xray runs but does nothing until you replace it."
	fi
	echo "Remember to put your actual config in ${CONFIG_PATH}, then check"
	echo "and apply it:"
	echo "  sudo ${BIN_PATH} run -test -config ${CONFIG_PATH}"
	echo "  sudo systemctl restart xray"
}

install_all() {
	[ -f xray ] || die "./xray not found; run ./build.sh first"
	./xray version >/dev/null 2>&1 || die "./xray does not run on this machine (built for another OS/arch?)"

	mkdir -p "${DESTDIR}$(dirname "${BIN_PATH}")" "${DESTDIR}${CONFIG_DIR}" \
		"${DESTDIR}${SHARE_DIR}" "${DESTDIR}${LOG_DIR}" "${DESTDIR}$(dirname "${UNIT_PATH}")"

	# Replace the binary atomically so a running service is never left with a
	# half-written file.
	info "Installing $(./xray version | sed -n 1p) to ${BIN_PATH}"
	install -m 755 xray "${DESTDIR}${BIN_PATH}.new"
	mv -f "${DESTDIR}${BIN_PATH}.new" "${DESTDIR}${BIN_PATH}"

	if [ ! -e "${DESTDIR}${CONFIG_PATH}" ]; then
		info "Creating an empty ${CONFIG_PATH}; edit it before use"
		echo '{}' >"${DESTDIR}${CONFIG_PATH}"
	else
		info "Keeping existing ${CONFIG_PATH}"
	fi
	# The config holds keys and passwords: readable by root and the service only.
	chmod 640 "${DESTDIR}${CONFIG_PATH}"
	if live; then
		ensure_user
		chgrp "${SERVICE_USER}" "${CONFIG_DIR}" "${CONFIG_PATH}"
		chmod 750 "${CONFIG_DIR}"
		chown "${SERVICE_USER}:" "${LOG_DIR}"
	fi

	if [ "${geodata}" = 1 ]; then
		install_geodata
	fi

	info "Writing ${UNIT_PATH}"
	write_unit

	if ! live; then
		info "Staged under ${DESTDIR}"
		config_reminder
		return
	fi

	systemctl daemon-reload
	systemctl enable xray.service >/dev/null 2>&1
	if ! "${BIN_PATH}" run -test -config "${CONFIG_PATH}" >/dev/null 2>&1; then
		warn "${CONFIG_PATH} is invalid; not (re)starting. Check it with:"
		warn "  ${BIN_PATH} run -test -config ${CONFIG_PATH}"
		warn "then run: systemctl restart xray"
		exit 1
	fi
	info "Restarting xray.service"
	systemctl restart xray.service
	sleep 1
	if systemctl is-active --quiet xray.service; then
		info "xray is running. Logs: journalctl -u xray -f"
		config_reminder
	else
		die "xray.service failed to start; see: journalctl -u xray -e"
	fi
}

preflight "$@"
case "${action}" in
install) install_all ;;
uninstall) uninstall ;;
esac
