#!/usr/bin/env python3
"""Build the architecture-independent OpenWrt 24.10 IPK without an SDK."""
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile

BASE = Path(__file__).resolve().parents[1]
NAME = "luci-app-nava"
VERSION = "1.0.0-30"
DEPENDENCIES = "luci-base, rpcd, python3, curl, ca-bundle, kmod-tun, kmod-nft-tproxy, kmod-nft-queue, ip-full, firewall4, conntrack"


def archive(entries, directory_modes=None):
    entries = list(entries)
    directory_modes = directory_modes or {}
    directories = {str(parent) for path, _, _ in entries for parent in PurePosixPath(path).parents if str(parent) != '.'}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as tar:
        # opkg expects directory entries before the files they contain. Python's
        # tar extractor creates missing parents for files; opkg's default does not.
        for path in sorted(directories, key=lambda p: (len(PurePosixPath(p).parts), p)):
            info = tarfile.TarInfo("./" + path + "/")
            info.type = tarfile.DIRTYPE
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            info.mode = directory_modes.get(path, 0o755)
            tar.addfile(info)
        for path, data, mode in sorted(entries):
            info = tarfile.TarInfo("./" + path)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            info.mode = mode
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def build():
    entries = []
    for source, prefix in ((BASE / NAME / "root", ""), (BASE / NAME / "htdocs", "www/")):
        for path in source.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.name.startswith("."):
                continue
            dest = prefix + path.relative_to(source).as_posix()
            mode = 0o755 if dest.startswith(("etc/init.d/", "etc/uci-defaults/", "usr/libexec/")) else 0o644
            if dest.startswith("etc/nava/"):
                mode = 0o600
            entries.append((dest, path.read_bytes(), mode))
    data = archive(entries, {"etc/nava": 0o700})
    control = ("Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: Nava contributors\n"
               "Section: luci\nPriority: optional\nLicense: MIT\nDepends: %s\nInstalled-Size: %s\n"
               "Description: English LuCI subscription manager for sing-box\n" %
               (NAME, VERSION, DEPENDENCIES, sum(len(item[1]) for item in entries))).encode()
    postinst = b'''#!/bin/sh
set -e
[ -n "$IPKG_INSTROOT" ] && exit 0
for file in /etc/nava/settings.json /usr/lib/nava/manager.py /usr/lib/nava/subscription.py /usr/lib/nava/dns_forwarding.py /usr/lib/nava/network_cleanup.py /usr/lib/nava/diagnostics.py /usr/lib/nava/routing.py /usr/libexec/rpcd/nava /www/luci-static/resources/nava/nava.css; do
    if [ ! -f "$file" ]; then
        echo "Nava installation incomplete: missing $file" >&2
        exit 1
    fi
done
umask 077
mkdir -p /etc/nava /usr/lib/nava/core
chmod 700 /etc/nava /usr/lib/nava/core
if [ -f /etc/uci-defaults/90-nava ]; then
    sh /etc/uci-defaults/90-nava
    rm -f /etc/uci-defaults/90-nava
fi
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd restart
exit 0
'''
    prerm = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
/etc/init.d/nava stop
/etc/init.d/nava disable
exit 0
'''
    package = archive([
        ("debian-binary", b"2.0\n", 0o644),
        ("data.tar.gz", data, 0o644),
        ("control.tar.gz", archive([("control", control, 0o644), ("conffiles", b"/etc/nava/settings.json\n", 0o644), ("postinst", postinst, 0o755),
                                    ("prerm", prerm, 0o755)]), 0o644)
    ])
    output = BASE / "dist"
    output.mkdir(exist_ok=True)
    path = output / (NAME + "_" + VERSION + "_all.ipk")
    path.write_bytes(package)
    (output / "SHA256SUMS").write_text(hashlib.sha256(package).hexdigest() + "  " + path.name + "\n")
    print(path)
    print("%d bytes; core is downloaded on the router, not bundled." % len(package))
    return path


if __name__ == "__main__":
    build()
