#!/bin/sh
set -eu

if [ "$(id -u)" != 0 ] || [ ! -f /etc/openwrt_release ]; then
	echo "Run this installer as root on your OpenWrt router." >&2
	exit 1
fi
if ! command -v opkg >/dev/null 2>&1; then
	echo "This IPK installer targets OpenWrt 24.10 with opkg." >&2
	exit 1
fi
if [ "$#" != 1 ] || [ ! -f "$1" ]; then
	echo "Usage: sh install.sh /tmp/luci-app-nava_1.0.0-30_all.ipk" >&2
	exit 1
fi

opkg update
opkg install "$1"
echo "Installed. Open LuCI > Services > NARA. Add a subscription, choose it in Connection, then click Apply & reconnect."
