"""Root-owned rpcd backend. Long operations run outside rpcd's request timeout."""
import fcntl
import routing
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import ipaddress
import socket
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

from subscription import NavaError, MAX_BYTES, build_config, parse_subscription_bundle

DATA = Path("/etc/nava")
RUN = Path("/var/run/nava")
CORE = Path("/usr/lib/nava/core/sing-box")
SERVICE = "/etc/init.d/nava"
RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
APP_VERSION = "1.0.0-30"
TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULTS = {"subscription_url": "", "subscriptions": [], "active_subscription": "", "selected": "auto",
            "ipv6": True, "autostart": False, "dns_mode": "default", "custom_dns": "",
            "skin": "default", "routing": {"enabled": False, "ip_source": "ir", "domain_source": "ir", **{key: "" for key in routing.CUSTOM_FIELDS}}}
METHODS = {"status": {}, "subscription": {"subscription_id": ""}, "action": {"action": "", "subscription_url": "", "subscription_id": "",
                                      "subscription_name": "", "selected": "", "ipv6": True, "autostart": True,
                                      "dns_mode": "default", "custom_dns": "", "test_target": "google",
                                      "skin": "default", "routing_enabled": False, "ip_source": "ir", "domain_source": "ir", **{key: "" for key in routing.CUSTOM_FIELDS}}}
ACTIONS = {"connect", "disconnect", "refresh", "update", "probe", "save", "select_subscription", "delete_subscription",
           "add_subscription", "edit_subscription", "update_subscription", "test_subscriptions",
           "update_all_subscriptions", "save_general", "save_routing", "update_routing"}


def read_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".nava-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, ensure_ascii=False, separators=(",", ":"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def ip_command(args):
    # OpenWrt can install ip-full without changing /sbin/ip (BusyBox). JSON
    # inspection and scoped policy cleanup require the installed full binary.
    if args and args[0] == "ip":
        for binary in ("/usr/libexec/ip-full", "/usr/sbin/ip-full", "/sbin/ip-full"):
            if os.access(binary, os.X_OK):
                return [binary, *args[1:]]
        binary = shutil.which("ip-full")
        if binary:
            return [binary, *args[1:]]
    return args


def command(args, timeout=20, label=None, **kwargs):
    label = label or str(args[0])
    args = ip_command(args)
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
    except FileNotFoundError:
        raise NavaError("Required command is missing: %s. Install the package dependencies and try again." % label) from None
    except PermissionError:
        raise NavaError("Required command cannot be executed: %s. Check its permissions." % label) from None
    except subprocess.TimeoutExpired:
        raise NavaError("%s timed out after %d seconds. Check router Internet access and DNS." % (label, timeout)) from None
    except OSError as exc:
        raise NavaError("%s could not run (%s). Check the installed dependencies." % (label, exc.strerror or "system error")) from None


def _subscription_id(url):
    return "sub-" + hashlib.sha256(url.encode()).hexdigest()[:16]


def _safe_subscription_name(value, fallback):
    value = value if isinstance(value, str) else ""
    value = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()[:80]
    return value or fallback


def _subscription_display_url(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = ":%d" % port if port and port != default_port else ""
    return "%s://%s%s" % (parsed.scheme, host, suffix)


def settings():
    raw = read_json(DATA / "settings.json", {})
    if not isinstance(raw, dict):
        raw = {}
    value = {**DEFAULTS, **raw}
    for key in ("routing_enabled", "geoip_source", "geosite_source"):
        value.pop(key, None)
    subscriptions = []
    raw_subscriptions = raw.get("subscriptions")
    if isinstance(raw_subscriptions, list):
        for index, item in enumerate(raw_subscriptions, 1):
            if not isinstance(item, dict) or not isinstance(item.get("url"), str) or not item["url"].strip():
                continue
            url = item["url"].strip()
            try:
                validate_url(url)
            except NavaError:
                continue
            sid = item.get("id") if isinstance(item.get("id"), str) and re.fullmatch(r"sub-[a-f0-9]{16}", item["id"]) else _subscription_id(url)
            if any(existing["id"] == sid for existing in subscriptions):
                continue
            subscriptions.append({"id": sid, "name": _safe_subscription_name(item.get("name"), "Subscription %d" % index), "url": url})
    # Migrate the original single-link format on first use.
    if not subscriptions and isinstance(raw.get("subscription_url"), str) and raw["subscription_url"].strip():
        url = raw["subscription_url"].strip()
        try:
            validate_url(url)
            subscriptions = [{"id": _subscription_id(url), "name": "Subscription 1", "url": url}]
        except NavaError:
            pass
    active = raw.get("active_subscription") if isinstance(raw.get("active_subscription"), str) else ""
    if "active_subscription" not in raw or (not raw_subscriptions and raw.get("subscription_url") and subscriptions):
        active = subscriptions[0]["id"] if subscriptions else ""
    elif active and active not in {item["id"] for item in subscriptions}:
        active = ""
    active_url = next((item["url"] for item in subscriptions if item["id"] == active), "")
    value["subscriptions"] = subscriptions
    value["active_subscription"] = active
    value["subscription_url"] = active_url
    if value.get("dns_mode") not in {"default", "cloudflare", "google", "opendns", "custom"}:
        value["dns_mode"] = "default"
    if not isinstance(value.get("custom_dns"), str):
        value["custom_dns"] = ""
    if not isinstance(value.get("skin"), str) or value["skin"] not in {"default", "orange"}:
        value["skin"] = "default"
    value["routing"] = routing.normalize(value.get("routing"))
    return value


def validate_settings(params):
    value = settings()
    action = params.get("action", "")
    if action == "update_routing":
        return value
    if action == "save_routing":
        enabled = params.get("routing_enabled")
        ip_source, domain_source = params.get("ip_source"), params.get("domain_source")
        if (not isinstance(enabled, bool) or not isinstance(ip_source, str) or not isinstance(domain_source, str)
                or ip_source not in routing.SOURCES or domain_source not in routing.SOURCES):
            raise NavaError("Invalid routing settings.")
        custom = routing.validate_custom({key: params.get(key, value["routing"].get(key, "")) for key in routing.CUSTOM_FIELDS})
        value["routing"] = {"enabled": enabled, "ip_source": ip_source, "domain_source": domain_source, **custom}
        return value
    if action == "save_general":
        skin = params.get("skin", value["skin"])
        if not isinstance(skin, str) or skin not in {"default", "orange"}:
            raise NavaError("Invalid skin selection.")
        value["skin"] = skin
        return value
    if action == "update_all_subscriptions":
        return value
    if action == "test_subscriptions":
        from diagnostics import TARGETS
        target = params.get("test_target", "google")
        if target not in TARGETS:
            raise NavaError("Invalid URL Test target.")
        return {**value, "test_target": target}
    url = params.get("subscription_url", "")
    if not isinstance(url, str):
        raise NavaError("Subscription URL must be text.")
    url = url.strip()
    requested_subscription_id = params.get("subscription_id", value["active_subscription"])
    if not isinstance(requested_subscription_id, str):
        raise NavaError("Invalid subscription selection.")
    if action in {"add_subscription", "edit_subscription", "update_subscription", "delete_subscription"}:
        item = next((item for item in value["subscriptions"] if item["id"] == requested_subscription_id), None)
        if action == "add_subscription":
            if not url:
                raise NavaError("Enter a subscription URL first.")
            validate_url(url)
            if any(entry["url"] == url for entry in value["subscriptions"]):
                raise NavaError("This subscription URL is already saved.")
            requested_subscription_id = _subscription_id(url)
            salt = 0
            while any(entry["id"] == requested_subscription_id for entry in value["subscriptions"]):
                salt += 1
                requested_subscription_id = _subscription_id(url + "\n%d" % salt)
            value["subscriptions"].append({"id": requested_subscription_id, "url": url,
                "name": _safe_subscription_name(params.get("subscription_name"), "Subscription %d" % (len(value["subscriptions"]) + 1))})
        elif item is None:
            raise NavaError("Selected subscription no longer exists.")
        elif action == "edit_subscription":
            if url:
                validate_url(url)
                if any(entry["id"] != item["id"] and entry["url"] == url for entry in value["subscriptions"]):
                    raise NavaError("This subscription URL is already saved.")
                item["url"] = url
            item["name"] = _safe_subscription_name(params.get("subscription_name"), item["name"])
        elif action == "delete_subscription":
            value["subscriptions"] = [entry for entry in value["subscriptions"] if entry["id"] != item["id"]]
            if value["active_subscription"] == item["id"]:
                value["active_subscription"] = ""
                value["selected"] = "auto"
        value["subscription_url"] = next((entry["url"] for entry in value["subscriptions"] if entry["id"] == value["active_subscription"]), "")
        value["operation_subscription"] = requested_subscription_id
        return value
    # An empty ID plus a new URL means “add a subscription”; an empty ID on
    # operations without a URL means “keep the active subscription”.
    subscription_id = requested_subscription_id if (requested_subscription_id or url) else value["active_subscription"]
    if url and action not in {"select_subscription", "delete_subscription"}:
        validate_url(url)
        name = _safe_subscription_name(params.get("subscription_name"), "Subscription %d" % (len(value["subscriptions"]) + 1))
        existing = next((item for item in value["subscriptions"] if item["id"] == subscription_id), None)
        if existing is None:
            subscription_id = _subscription_id(url)
            existing = next((item for item in value["subscriptions"] if item["id"] == subscription_id), None)
        if existing is None:
            value["subscriptions"].append({"id": subscription_id, "name": name, "url": url})
        else:
            existing["url"] = url
            existing["name"] = name if params.get("subscription_name") else existing.get("name", name)
    ids = {item["id"] for item in value["subscriptions"]}
    if not url and subscription_id in ids and isinstance(params.get("subscription_name"), str) and params.get("subscription_name").strip():
        item = next(item for item in value["subscriptions"] if item["id"] == subscription_id)
        item["name"] = _safe_subscription_name(params["subscription_name"], item["name"])
    if subscription_id and subscription_id not in ids:
        raise NavaError("Selected subscription no longer exists.")
    value["active_subscription"] = subscription_id if subscription_id in ids else ""
    value["subscription_url"] = next((item["url"] for item in value["subscriptions"] if item["id"] == value["active_subscription"]), "")
    if action in {"connect", "refresh"} and not value["active_subscription"]:
        raise NavaError("Enter a subscription URL first.")
    for key in ("ipv6", "autostart"):
        if key in params:
            if not isinstance(params[key], bool):
                raise NavaError("Invalid option type.")
            value[key] = params[key]
    selected = params.get("selected", value["selected"])
    if not isinstance(selected, str) or not re.fullmatch(r"auto|node-[a-f0-9]{16}", selected):
        raise NavaError("Invalid server selection.")
    value["selected"] = selected
    mode = params.get("dns_mode", value.get("dns_mode", "default"))
    if mode not in {"default", "cloudflare", "google", "opendns", "custom"}:
        raise NavaError("Invalid DNS selection.")
    custom_dns = params.get("custom_dns", value.get("custom_dns", ""))
    if not isinstance(custom_dns, str) or len(custom_dns) > 2048:
        raise NavaError("Invalid custom DNS value.")
    value["dns_mode"], value["custom_dns"] = mode, custom_dns.strip()
    return value


def validate_url(url):
    try:
        parsed = urlsplit(url)
        if (len(url) > 4096 or re.search(r"[\s\x00-\x1f\x7f]", url) or parsed.scheme not in {"http", "https"}
                or not parsed.hostname or parsed.username or parsed.password or parsed.fragment):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
    except ValueError:
        raise NavaError("Enter an HTTP or HTTPS subscription URL without embedded user/password or fragment.") from None


def download(url, destination, limit=MAX_BYTES, core=False, label=None):
    validate_url(url)
    args = ["curl", "-q", "--fail", "--silent", "--show-error", "--location", "--max-redirs", "5",
            "--proto", "=http,https", "--proto-redir", "=http,https", "--connect-timeout", "20", "--max-time", "240" if core else "60",
            "--max-filesize", str(limit), "--noproxy", "*", "--user-agent", "Nava/1.0 sing-box",
            "--output", str(destination), "--config", "-"]
    if core:
        args += ["--retry", "2", "--retry-delay", "2"]
    # Keep subscription tokens out of process listings, error messages and the shell.
    config = 'url = "' + url.replace("\\", "\\\\").replace('"', '\\"') + '"\n'
    kind = label or ("sing-box core download" if core else "subscription download")
    result = command(args, timeout=760 if core else 70, label=kind, input=config)
    if result.returncode:
        message = {5: "Proxy lookup failed.", 6: "DNS lookup failed.", 7: "Connection failed.",
                   18: "The download was incomplete.", 22: "The server returned an HTTP error.",
                   23: "The router could not write the download. Check free storage.",
                   28: "Download timed out.", 35: "TLS handshake failed.",
                   47: "Too many redirects.", 52: "The server returned no response.",
                   56: "The connection was interrupted.", 60: "TLS certificate verification failed. Check the router clock.",
                   63: "Download is too large."}.get(result.returncode, "Download failed (curl exit %d)." % result.returncode)
        raise NavaError("%s %s Check router Internet access, DNS and free storage." % (kind, message))
    if destination.stat().st_size > limit:
        destination.unlink()
        raise NavaError("Download exceeds the size limit.")


def architecture(elf=None, cpuinfo=None):
    """Read userspace ELF, not uname: 32-bit userspace can use a 64-bit kernel."""
    if elf is None:
        with open("/bin/busybox", "rb") as stream:
            elf = stream.read(64)
    if len(elf) < 20 or elf[:4] != b"\x7fELF" or elf[5] not in (1, 2):
        raise NavaError("Cannot determine the router CPU architecture.")
    bits, little = elf[4], elf[5] == 1
    machine = struct.unpack("<H" if little else ">H", elf[18:20])[0]
    if machine == 62 and bits == 2:
        return "amd64"
    if machine == 3 and bits == 1:
        return "386"
    if machine == 183 and bits == 2:
        return "arm64"
    if machine == 40 and bits == 1:
        cpuinfo = cpuinfo if cpuinfo is not None else Path("/proc/cpuinfo").read_text()
        match = re.search(r"CPU architecture\s*:\s*(\d+)", cpuinfo)
        level = int(match.group(1)) if match else 5
        # ARMv5 is a compatible conservative fallback for unknown older ARM CPUs.
        return "armv7" if level >= 7 else "armv6" if level == 6 else "armv5"
    if machine == 8:
        return "mips" + ("64" if bits == 2 else "") + ("le" if little else "") + "-softfloat"
    if machine == 243 and bits == 2:
        return "riscv64"
    if machine == 258 and bits == 2:
        return "loong64"
    if machine == 21 and little and bits == 2:
        return "ppc64le"
    raise NavaError("This CPU architecture has no supported official core build.")


def choose_asset(release, arch):
    tag = release.get("tag_name", "")
    if release.get("prerelease") or release.get("draft") or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise NavaError("GitHub did not return a stable release.")
    if tuple(map(int, tag[1:].split("."))) < (1, 14, 0):
        raise NavaError("sing-box 1.14 or newer is required.")
    # OpenWrt uses musl. Prefer the explicitly musl-linked build; the generic
    # asset remains a compatibility fallback for architectures without one.
    names = ["sing-box-%s-linux-%s-musl.tar.gz" % (tag[1:], arch),
             "sing-box-%s-linux-%s.tar.gz" % (tag[1:], arch)]
    asset = next((a for candidate in names for a in release.get("assets", []) if a.get("name") == candidate), None)
    if not asset:
        raise NavaError("The latest release has no binary for this router architecture.")
    name = asset.get("name")
    if not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", asset.get("digest") or ""):
        raise NavaError("The release has no SHA-256 digest. Installation was refused.")
    expected_url = "https://github.com/SagerNet/sing-box/releases/download/%s/%s" % (tag, name)
    if asset.get("browser_download_url") != expected_url:
        raise NavaError("Unexpected release download URL.")
    if not isinstance(asset.get("size"), int) or not 0 < asset["size"] <= 100 * 1024 * 1024:
        raise NavaError("Unexpected core download size.")
    return tag[1:], asset


def extract_core(archive, output):
    with tarfile.open(archive, "r:gz") as bundle:
        members = [m for m in bundle if m.name.endswith("/sing-box") or m.name == "sing-box"]
        if len(members) != 1:
            raise NavaError("Core archive must contain exactly one binary.")
        member = members[0]
        if not member.isfile() or not 0 < member.size <= 200 * 1024 * 1024:
            raise NavaError("Invalid core archive member.")
        if member.name.startswith("/") or ".." in Path(member.name).parts:
            raise NavaError("Unsafe core archive path.")
        if shutil.disk_usage(output.parent).free < member.size + 8 * 1024 * 1024:
            raise NavaError("Not enough persistent storage for the new core and rollback copy.")
        # Never extract paths, symlinks, permissions or other archive entries.
        with bundle.extractfile(member) as src, output.open("wb") as dest:
            shutil.copyfileobj(src, dest, 128 * 1024)
    output.chmod(0o700)


def core_version(binary=None):
    binary = CORE if binary is None else binary
    if not binary.is_file():
        return None
    result = command([str(binary), "version"], timeout=10, label="sing-box core")
    match = re.search(r"sing-box version (\S+)", result.stdout)
    return match.group(1) if result.returncode == 0 and match else None


def running():
    try:
        result = command(["ubus", "call", "service", "list", '{"name":"nava"}'], timeout=5, label="ubus")
        services = json.loads(result.stdout)
        # Only the tunnel instance determines connection state. A DNS watcher
        # or another auxiliary process must never authorize starting a tunnel.
        return bool(services.get("nava", {}).get("instances", {}).get("core", {}).get("running", False))
    except (NavaError, ValueError):
        return False


def service(action):
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise NavaError("Invalid service action.")
    if command([SERVICE, action], timeout=90, label="NARA service").returncode:
        for filename in ("network-status.json", "dns-status.json"):
            state = read_json(RUN / filename, {})
            if state.get("state") == "error" and isinstance(state.get("message"), str):
                raise NavaError(state["message"])
        raise NavaError("Could not %s the router service." % action)


def wait_running():
    for _ in range(15):
        time.sleep(1)
        if running():
            time.sleep(2)
            if running():
                return
    raise NavaError("The core could not start. The previous working configuration has been restored.")


def check_config(binary, path):
    result = command([str(binary), "check", "-c", str(path)], timeout=30, label="sing-box configuration check")
    if result.returncode:
        # Raw core errors may contain credentials, so only expose an outbound index.
        dns_rule = re.search(r"dns rule\[(\d+)\]", result.stderr)
        if "rule-set not found" in result.stderr:
            suffix = " (DNS rule %s)" % dns_rule.group(1) if dns_rule else ""
            raise NavaError("Subscription DNS references a missing rule set%s. Update the subscription or choose a DNS override. The previous connection has been kept." % suffix)
        if "missing `route.default_domain_resolver`" in result.stderr:
            raise NavaError("Subscription DNS is missing a required domain resolver. Choose a DNS override or request a compatible subscription. The previous connection has been kept.")
        if "initialize dns" in result.stderr.lower() or "dns.servers[" in result.stderr.lower():
            raise NavaError("Core rejected the DNS configuration. Check the selected DNS or subscription DNS settings. The previous connection has been kept.")
        index = re.search(r"outbounds\[(\d+)\]", result.stderr)
        suffix = " (outbound %s)" % index.group(1) if index else ""
        raise NavaError("Core rejected the configuration%s. Check protocol, transport and credentials." % suffix)


def job_update(stage, message, **extra):
    old = read_json(RUN / "job.json", {})
    atomic_json(RUN / "job.json", {**old, "stage": stage, "message": message, "updated": int(time.time()), **extra})


def update_core():
    job_update("download", "Checking the latest stable release…")
    CORE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="nava-update-", dir=str(RUN)) as temp:
        temp = Path(temp)
        download(RELEASE_API, temp / "release.json", limit=4 * 1024 * 1024)
        release = read_json(temp / "release.json", {})
        version, asset = choose_asset(release, architecture())
        if core_version() == version:
            atomic_json(DATA / "core.json", {"version": version, "checked": int(time.time())})
            return version
        if shutil.disk_usage(RUN).free < asset["size"] + 8 * 1024 * 1024:
            raise NavaError("Not enough temporary storage to download the core.")
        job_update("download", "Downloading sing-box %s…" % version)
        archive = temp / "core.tar.gz"
        download(asset["browser_download_url"], archive, limit=asset["size"], core=True)
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for chunk in iter(lambda: stream.read(128 * 1024), b""):
                digest.update(chunk)
        if archive.stat().st_size != asset["size"] or digest.hexdigest() != asset["digest"].split(":", 1)[1].lower():
            raise NavaError("Core checksum mismatch. The current core has been kept.")
        candidate = CORE.with_name("sing-box.new")
        backup = CORE.with_name("sing-box.previous")
        try:
            extract_core(archive, candidate)
            if core_version(candidate) != version:
                raise NavaError("The downloaded core cannot run on this router.")
            config = DATA / "config.json"
            if config.exists():
                check_config(candidate, config)
            was_running = running()
            had_core = CORE.exists()
            if was_running:
                (RUN / "health.json").unlink(missing_ok=True)
                service("stop")
            if had_core:
                os.replace(CORE, backup)
            try:
                os.replace(candidate, CORE)
                if was_running:
                    service("start")
                    wait_running()
                    wait_dns()
            except Exception:
                if was_running:
                    service("stop")
                if had_core:
                    os.replace(backup, CORE)
                else:
                    CORE.unlink(missing_ok=True)
                if was_running:
                    service("start")
                raise
            atomic_json(DATA / "core.json", {"version": version, "checked": int(time.time()), "sha256": asset["digest"]})
            return version
        finally:
            candidate.unlink(missing_ok=True)


def fetch_subscription(config):
    if not config["subscription_url"]:
        raise NavaError("Enter a subscription URL first.")
    job_update("subscription", "Downloading your subscription…")
    with tempfile.TemporaryDirectory(prefix="nava-sub-", dir=str(RUN)) as temp:
        path = Path(temp) / "subscription"
        download(config["subscription_url"], path)
        nodes, warnings, subscription_dns, dns_context = parse_subscription_bundle(path.read_bytes(), include_context=True)
    return {"nodes": nodes, "dns": subscription_dns, "dns_context": dns_context, "warnings": warnings[:50], "warning_count": len(warnings), "updated": int(time.time()),
            "source_hash": hashlib.sha256(config["subscription_url"].encode()).hexdigest()}


def active_cache(config):
    raw = read_json(DATA / "subscription.json", {})
    if isinstance(raw, dict) and isinstance(raw.get("entries"), dict):
        return raw["entries"].get(config.get("active_subscription"), {})
    # Read the cache written by revisions 1.0.0-1 through 1.0.0-3.
    return raw if isinstance(raw, dict) and isinstance(raw.get("nodes"), list) else {}


def save_cache(config, cache):
    raw = read_json(DATA / "subscription.json", {})
    entries = raw.get("entries", {}) if isinstance(raw, dict) and isinstance(raw.get("entries"), dict) else {}
    if not entries and isinstance(raw, dict) and isinstance(raw.get("nodes"), list):
        for item in config.get("subscriptions", []):
            if raw.get("source_hash") == hashlib.sha256(item["url"].encode()).hexdigest():
                entries[item["id"]] = raw
    entries[config.get("active_subscription", "")] = cache
    atomic_json(DATA / "subscription.json", {"entries": entries, "active_subscription": config.get("active_subscription", "")})


def prepare_dns_bootstrap(config):
    # Pin hostname-only bootstrap before dnsmasq forwards to sing-box, avoiding
    # a loop through system-dns back into this same resolver.
    for server in config.get("dns", {}).get("servers", []):
        if server.get("tag") != "bootstrap" or not server.get("server"):
            continue
        host = server["server"]
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        try:
            addresses = socket.getaddrinfo(host, server.get("server_port", 53), type=socket.SOCK_DGRAM)
            server["server"] = addresses[0][4][0]
        except OSError:
            raise NavaError("Cannot resolve the custom DNS hostname. Enter a DNS IP address and reconnect.") from None
        if server.get("type") in {"tls", "https", "quic", "http3"}:
            server.setdefault("tls", {}).setdefault("server_name", host)
        server.pop("domain_resolver", None)
    return config


def wait_dns(config=None):
    if not any(item.get("tag") == "nava-dns-in" for item in read_json(DATA / "config.json", {}).get("inbounds", [])):
        return
    for _ in range(35):
        state = read_json(RUN / "dns-status.json", {})
        if state.get("state") == "ready":
            return
        if state.get("state") == "error":
            raise NavaError(state.get("message") or "DNS forwarding failed.")
        time.sleep(1)
    raise NavaError("DNS forwarding did not start. The previous connection has been restored.")


def subscription_details(params):
    item = next((item for item in settings()["subscriptions"] if item["id"] == params.get("subscription_id")), None)
    if not item:
        raise NavaError("Selected subscription no longer exists.")
    return {"ok": True, "id": item["id"], "name": item["name"], "url": item["url"]}


def subscription_tests(item, cache):
    result = read_json(DATA / "tests.json", {}).get("entries", {}).get(item["id"], {})
    if result.get("source_hash") != hashlib.sha256(item["url"].encode()).hexdigest():
        return {}
    if not result.get("error") and result.get("cache_updated") != cache.get("updated"):
        return {}
    return result


def prepare_proxy_endpoints(generated, selected="auto", ipv6=True):
    """Resolve only VPN endpoints before retiring the working DNS path.

    Keep Default free of a DNS engine. Numeric runtime endpoints let the
    tunnel start without asking the not-yet-connected tunnel for its own IP.
    Subscription data is unchanged; reconnect resolves the hostnames again.
    """
    automatic = next(item for item in generated["outbounds"] if item["tag"] == "auto")
    required = set(automatic["outbounds"]) if selected == "auto" else {selected}
    answers, failed = {}, set()
    for outbound in generated["outbounds"]:
        if outbound.get("tag") not in required:
            continue
        host = outbound.get("server", "")
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if host not in answers:
            try:
                records = socket.getaddrinfo(host, outbound.get("server_port", 443),
                                             family=socket.AF_UNSPEC if ipv6 else socket.AF_INET,
                                             type=socket.SOCK_STREAM)
                addresses = [row[4][0] for row in records if row[0] in (socket.AF_INET, socket.AF_INET6)
                             and (ipv6 or row[0] == socket.AF_INET)]
                addresses.sort(key=lambda address: ipaddress.ip_address(address).version)
                answers[host] = addresses[0] if addresses else None
            except (OSError, ValueError):
                answers[host] = None
        address = answers[host]
        if not address:
            failed.add(outbound["tag"])
            continue
        outbound["server"] = address
        tls = outbound.get("tls", {})
        if tls.get("enabled") and not tls.get("server_name"):
            tls["server_name"] = host
        transport = outbound.get("transport", {})
        if transport.get("type") == "ws":
            headers = transport.setdefault("headers", {})
            if not any(key.lower() == "host" for key in headers):
                headers["Host"] = host
        elif transport.get("type") in {"http", "httpupgrade"} and not transport.get("host"):
            transport["host"] = [host] if transport["type"] == "http" else host
    if failed == required or selected in failed:
        raise NavaError("Could not resolve the VPN server before reconnecting. The previous connection has been kept.")
    if failed:
        # One expired hostname must not block Automatic from using healthy
        # servers, nor become its initial DNS-dependent fallback. Exclusions
        # last for this runtime only; the cached library stays intact.
        generated["outbounds"] = [item for item in generated["outbounds"] if item["tag"] not in failed]
        for item in generated["outbounds"]:
            if item.get("type") in {"urltest", "selector"}:
                item["outbounds"] = [tag for tag in item["outbounds"] if tag not in failed]
    return generated


def connection_config(config, cache):
    generated = build_config(cache["nodes"], config["selected"], config["ipv6"], config.get("dns_mode", "default"),
                             config.get("custom_dns", ""), cache.get("dns"), cache.get("dns_context"))
    if config.get("dns_mode", "default") != "default":
        generated = prepare_dns_bootstrap(generated)
    return routing.apply(generated, config, read_json(DATA / "routing-state.json", {}), DATA)


def activate(config, cache):
    candidate = DATA / "config.new.json"
    current = DATA / "config.json"
    old = current.read_bytes() if current.exists() else None
    was_running = running()
    old_health = read_json(RUN / "health.json", {})
    effective = config
    try:
        generated = connection_config(config, cache)
        if config.get("dns_mode", "default") == "default":
            job_update("endpoints", "Preparing VPN server addresses before reconnecting…")
            generated = prepare_proxy_endpoints(generated, config["selected"], config["ipv6"])
        prepared_outbounds = generated["outbounds"]
        atomic_json(candidate, generated)
        job_update("validate", "Validating the connection settings…")
        check_config(CORE, candidate)
        (RUN / "health.json").unlink(missing_ok=True)
        service("stop")
        os.replace(candidate, current)
        try:
            job_update("start", "Starting the tunnel…")
            service("start")
            wait_running()
            wait_dns(config)
            verified = probe()
            health = read_json(RUN / "health.json", {})
            if (not verified and config["ipv6"] and health.get("proxy_ok") and
                    health.get("tunnel_ipv4_ok") and not health.get("tunnel_ok")):
                # A TUN can acknowledge IPv6 before the proxy can deliver it.
                # The browser then stops racing IPv4 and waits on a dead path.
                # Retry with the existing public IPv6 rejection rule; DNS and
                # WAN settings are untouched. Persist this only after success.
                effective = {**config, "ipv6": False}
                job_update("ipv4", "IPv6 tunnel is unavailable. Retrying with IPv4…")
                generated = connection_config(effective, cache)
                if effective.get("dns_mode", "default") == "default":
                    generated["outbounds"] = prepared_outbounds
                atomic_json(candidate, generated)
                check_config(CORE, candidate)
                service("stop")
                os.replace(candidate, current)
                service("start")
                wait_running()
                wait_dns(effective)
                verified = probe()
            if not verified:
                health = read_json(RUN / "health.json", {})
                if health.get("proxy_ok") and not health.get("tunnel_ok"):
                    reason = "The proxy responds, but Internet access through the router tunnel failed."
                else:
                    reason = "Internet verification failed. Check the selected server and DNS."
                raise NavaError(reason + (" The previous connection has been restored." if was_running else
                                         " NARA was disconnected to restore direct Internet access."))
        except Exception:
            service("stop")
            if old is None:
                current.unlink(missing_ok=True)
            else:
                atomic_json(current, json.loads(old))
            if was_running:
                service("start")
                atomic_json(RUN / "health.json", old_health)
            else:
                (RUN / "health.json").unlink(missing_ok=True)
            raise
        atomic_json(DATA / "settings.json", effective)
        save_cache(effective, cache)
        apply_autostart(effective)
        return effective is not config
    finally:
        candidate.unlink(missing_ok=True)


def apply_autostart(config):
    service("enable" if config["autostart"] else "disable")


def probe():
    if not running():
        raise NavaError("Start the tunnel before testing the connection.")
    job_update("probe", "Checking Internet access through the proxy and router tunnel…")
    started = time.monotonic()
    def check(proxy, ipv4=False):
        args = ["curl", "-q", "--silent", "--fail", "--output", "/dev/null", "--write-out", "%{http_code}",
                "--connect-timeout", "5", "--max-time", "12"]
        args += ["--proxy", "http://127.0.0.1:2080", "--noproxy", ""] if proxy else ["--proxy", "", "--noproxy", "*"]
        if ipv4:
            args.append("--ipv4")
        try:
            result = command([*args, TEST_URL], timeout=15)
            return result.returncode == 0 and result.stdout.strip() == "204"
        except NavaError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        proxy_ok, tunnel_ok = list(pool.map(check, (True, False)))
    tunnel_ipv4_ok = check(False, ipv4=True) if proxy_ok and not tunnel_ok else tunnel_ok
    good = proxy_ok and tunnel_ok
    health = {"ok": good, "proxy_ok": proxy_ok, "tunnel_ok": tunnel_ok, "tunnel_ipv4_ok": tunnel_ipv4_ok, "checked": int(time.time()),
              "latency_ms": round((time.monotonic() - started) * 1000) if good else None, "target": "Google", "url": TEST_URL}
    atomic_json(RUN / "health.json", health)
    return good


def preflight():
    if not Path("/dev/net/tun").exists():
        raise NavaError("TUN support is missing. Install kmod-tun, then reboot if needed.")
    for name in ("curl", "ubus", "nft", "ip", "fw4"):
        if not shutil.which(name):
            raise NavaError("Required router component is missing: " + name)
    # Other transparent proxies can overwrite routes and firewall marks.
    if Path("/etc/init.d/sing-box").exists():
        result = command(["ubus", "call", "service", "list", '{"name":"sing-box"}'], timeout=5, label="ubus")
        try:
            instances = json.loads(result.stdout).get("sing-box", {}).get("instances", {})
        except ValueError:
            instances = {}
        if any(item.get("running") for item in instances.values()):
            raise NavaError("Stop the separate sing-box service before connecting NARA.")


def execute(action, config):
    if action == "save_routing":
        # Offline means settings only. Never stop/start/clean a service, load
        # runtime config, install a core, download lists or touch router DNS.
        if not running():
            atomic_json(DATA / "settings.json", config)
            return "Routing saved. It will apply when you connect."
        cache = active_cache(config)
        if not cache.get("nodes"):
            raise NavaError("Saved servers are unavailable. Update the active subscription first.")
        activate(config, cache)
        return "Routing applied. Internet access verified."
    if action == "update_routing":
        if not CORE.exists():
            update_core()
        manifest = routing.stage(DATA, CORE, download, command, check_config, job_update)
        atomic_json(DATA / "routing-state.json", manifest)
        routing.prune(DATA, manifest)
        return "Routing lists updated. Apply routing or reconnect to use them."
    if action == "save_general":
        atomic_json(DATA / "settings.json", config)
        return "Skin saved."
    if action == "update_all_subscriptions":
        if not config["subscriptions"]:
            raise NavaError("Add a subscription first.")
        succeeded, failures = 0, []
        for index, item in enumerate(config["subscriptions"], 1):
            job_update("subscriptions", "Updating subscription %d of %d…" % (index, len(config["subscriptions"])))
            target = {**config, "active_subscription": item["id"], "subscription_url": item["url"]}
            try:
                cache = fetch_subscription(target)
                save_cache(target, cache)
                succeeded += 1
            except NavaError as exc:
                failures.append("%s: %s" % (item["name"], str(exc)))
        message = "%d of %d subscriptions updated. Reconnect to apply updated servers." % (succeeded, len(config["subscriptions"]))
        if failures:
            raise NavaError(message + " Failed: " + "; ".join(failures[:5]))
        return message
    if action == "test_subscriptions":
        from diagnostics import test_all
        if not CORE.exists():
            update_core()
        return test_all(config)
    if action in {"add_subscription", "edit_subscription", "update_subscription", "delete_subscription"}:
        target_id = config.pop("operation_subscription")
        if action == "add_subscription":
            item = next(item for item in config["subscriptions"] if item["id"] == target_id)
            target = {**config, "active_subscription": target_id, "subscription_url": item["url"]}
            # Download and parse before committing the new link. Failure leaves
            # the existing library and active connection unchanged.
            cache = fetch_subscription(target)
            save_cache(target, cache)
            atomic_json(DATA / "settings.json", config)
            return "Subscription added and updated. %d servers loaded." % len(cache["nodes"])
        if action == "update_subscription":
            item = next(item for item in config["subscriptions"] if item["id"] == target_id)
            target = {**config, "active_subscription": target_id, "subscription_url": item["url"]}
            cache = fetch_subscription(target)
            save_cache(target, cache)
            return "%d servers loaded. Reconnect to apply the updated subscription." % len(cache["nodes"])
        old_item = next((item for item in settings()["subscriptions"] if item["id"] == target_id), None)
        new_item = next((item for item in config["subscriptions"] if item["id"] == target_id), None)
        if old_item and (new_item is None or old_item["url"] != new_item["url"]):
            raw_cache = read_json(DATA / "subscription.json", {})
            if isinstance(raw_cache, dict) and isinstance(raw_cache.get("entries"), dict):
                raw_cache["entries"].pop(target_id, None)
                atomic_json(DATA / "subscription.json", raw_cache)
            elif isinstance(raw_cache, dict) and raw_cache.get("source_hash") == hashlib.sha256(old_item["url"].encode()).hexdigest():
                atomic_json(DATA / "subscription.json", {"entries": {}})
        atomic_json(DATA / "settings.json", config)
        return {"add_subscription": "Subscription added.", "edit_subscription": "Subscription saved. Reconnect to apply changes.",
                "delete_subscription": "Subscription removed."}[action]
    if action == "disconnect":
        service("stop")
        service("disable")
        saved = settings()
        saved["autostart"] = False
        atomic_json(DATA / "settings.json", saved)
        (RUN / "health.json").unlink(missing_ok=True)
        return "Disconnected. Automatic start is off."
    if action == "update":
        version = update_core()
        if running():
            return "Core %s installed. %s" % (version, "Connection verified." if probe() else "Internet test failed; check your server.")
        return "Core %s is ready." % version
    if action == "probe":
        return "Connection verified." if probe() else "Tunnel is running, but the Internet test failed. Try another server."
    if action == "save":
        atomic_json(DATA / "settings.json", config)
        apply_autostart(config)
        return "Settings saved. Reconnect to apply connection changes."
    if action == "select_subscription":
        atomic_json(DATA / "settings.json", config)
        apply_autostart(config)
        return "Subscription selected. Connect to use it."
    if action == "refresh":
        cache = fetch_subscription(config)
        if config["selected"] not in ["auto"] + [n["id"] for n in cache["nodes"]]:
            config["selected"] = "auto"
        save_cache(config, cache)
        atomic_json(DATA / "settings.json", config)
        apply_autostart(config)
        return "%d servers loaded. Reconnect to use the updated subscription." % len(cache["nodes"])
    if action == "connect":
        preflight()
        # First connection installs latest. Later updates are explicit, so an API
        # outage cannot prevent an already provisioned router from reconnecting.
        if not CORE.exists():
            update_core()
        cache = active_cache(config)
        expected_hash = hashlib.sha256(config["subscription_url"].encode()).hexdigest()
        if not cache.get("nodes") or cache.get("source_hash") != expected_hash:
            cache = fetch_subscription(config)
        else:
            job_update("subscription", "Using saved subscription servers…")
        ipv4_fallback = activate(config, cache)
        return "Connected. Internet access verified." + (" IPv6 tunnel was unavailable; IPv6 traffic is now off." if ipv4_fallback else "")
    raise NavaError("Unknown operation.")


def busy():
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (RUN / "operation.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True


def status():
    from diagnostics import TARGETS
    config = settings()
    cache = active_cache(config)
    is_busy = busy()
    job = read_json(RUN / "job.json", {})
    if not is_busy and job.get("state") == "running":
        job = {**job, "state": "error", "message": "The operation was interrupted. Please retry."}
    is_running = running()
    raw_cache = read_json(DATA / "subscription.json", {})
    entries = raw_cache.get("entries", {}) if isinstance(raw_cache, dict) else {}
    def cache_for(sid):
        source = entries.get(sid, {}) if isinstance(entries, dict) else {}
        if sid == config["active_subscription"] and not source:
            source = cache
        return source
    def nodes_for(sid):
        source = cache_for(sid)
        return [{"id": n["id"], "name": n["name"], "type": n["outbound"]["type"],
                 "insecure": bool(n["outbound"].get("tls", {}).get("insecure"))} for n in source.get("nodes", [])]
    target = read_json(DATA / "tests.json", {}).get("target", "google")
    return {"ok": True, "app_version": APP_VERSION, "test_target": target if target in TARGETS else "google", "running": is_running, "busy": is_busy, "job": job,
            "health": read_json(RUN / "health.json", {}) if is_running else {},
            "dns_forwarding": read_json(RUN / "dns-status.json", {}) if is_running else {},
            "core": read_json(DATA / "core.json", {}) if CORE.exists() else {},
            "routing": routing.summary(read_json(DATA / "routing-state.json", {}), DATA),
            "settings": {k: config[k] for k in ("selected", "ipv6", "autostart", "active_subscription", "dns_mode", "custom_dns", "skin", "routing")},
            "subscriptions": [{"id": item["id"], "name": item["name"], "scheme": urlsplit(item["url"]).scheme,
                               "display_url": _subscription_display_url(item["url"]),
                               "nodes": nodes_for(item["id"]),
                               "updated": cache_for(item["id"]).get("updated"),
                               "tests": subscription_tests(item, cache_for(item["id"])),
                               "active": item["id"] == config["active_subscription"]} for item in config["subscriptions"]],
            "has_subscription": bool(config["subscriptions"]), "updated": cache.get("updated"),
            "nodes": [{"id": n["id"], "name": n["name"], "type": n["outbound"]["type"],
                       "insecure": bool(n["outbound"].get("tls", {}).get("insecure"))} for n in cache.get("nodes", [])],
            "warnings": cache.get("warnings", []), "warning_count": cache.get("warning_count", 0)}


def enqueue(params):
    action = params.get("action")
    if action not in ACTIONS:
        raise NavaError("Unknown operation.")
    config = validate_settings(params)
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = (RUN / "operation.lock").open("a")
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise NavaError("Another operation is in progress. Wait for it to finish.") from None
        operation_id = os.urandom(16).hex()
        atomic_json(RUN / "job.json", {"state": "running", "action": action, "stage": "queued", "message": "Preparing…", "updated": int(time.time()), "operation_id": operation_id,
                                      "requested_dns_mode": config["dns_mode"], "requested_subscription_id": config["active_subscription"]})
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "worker", action, str(lock.fileno())],
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True, close_fds=True, pass_fds=(lock.fileno(),))
        process.stdin.write(json.dumps(config).encode())
        process.stdin.close()
    finally:
        # The worker inherits the locked open file description and releases it on exit.
        lock.close()
    return {"ok": True, "accepted": True, "operation_id": operation_id}


def worker(action, descriptor):
    try:
        os.fstat(descriptor)
        # This private pipe contains the full validated settings, including all
        # saved links. The incoming RPC request limit is not a settings limit.
        config = json.loads(sys.stdin.buffer.read())
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
        message = execute(action, config)
        job_update("done", message, state="done")
    except NavaError as exc:
        job_update("error", str(exc), state="error")
    except Exception:
        job_update("error", "Unexpected system error. Check free storage and installed dependencies, then retry.", state="error")
    finally:
        os.close(descriptor)


def migrate_country_removal(data=None):
    """Remove the retired feature without choosing DNS or touching the network."""
    data = DATA if data is None else data
    path = data / "settings.json"
    saved = read_json(path, {})
    if isinstance(saved, dict):
        updated = {key: value for key, value in saved.items()
                   if key not in {"routing_enabled", "geoip_source", "geosite_source"}}
        if updated != saved:
            atomic_json(path, updated)
    path = data / "config.json"
    if path.exists():
        # Do not overwrite an unreadable saved configuration during upgrade.
        config = json.loads(path.read_text())
        route = config.get("route", {})
        owned = {"nava-" + country + "-" + kind
                 for country in ("ir", "cn", "ru") for kind in ("ip", "domain")}
        definitions = route.get("rule_set", [])
        retired = {item.get("tag") for item in definitions if item.get("tag") in owned}
        if retired:
            route["rule_set"] = [item for item in definitions if item.get("tag") not in retired]
            if not route["rule_set"]:
                route.pop("rule_set")
            route["rules"] = [rule for rule in route.get("rules", [])
                              if not (isinstance(rule.get("rule_set"), list) and
                                      rule["rule_set"] and set(rule["rule_set"]) <= retired)
                              and rule != {"inbound": ["health-in"], "action": "route", "outbound": "proxy"}
                              and rule != {"inbound": ["tun-in"], "action": "sniff", "sniffer": ["http", "tls", "quic"]}]
            atomic_json(path, config)
    # These paths were exclusively generated by the country-routing feature.
    (data / "routing.json").unlink(missing_ok=True)
    rules = data / "rules"
    if rules.is_symlink():
        rules.unlink()
    elif rules.exists():
        shutil.rmtree(rules)


def main():
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "migrate-country-removal":
        migrate_country_removal(Path(sys.argv[2]))
        return
    try:
        if len(sys.argv) >= 4 and sys.argv[1] == "worker":
            worker(sys.argv[2], int(sys.argv[3]))
            return
        if len(sys.argv) == 2 and sys.argv[1] == "list":
            result = METHODS
        elif len(sys.argv) == 3 and sys.argv[1] == "call":
            method = sys.argv[2]
            raw = sys.stdin.buffer.read(131073)
            if len(raw) > 131072:
                raise NavaError("Request is too large.")
            params = json.loads(raw or b"{}")
            if not isinstance(params, dict):
                raise NavaError("Invalid request.")
            result = status() if method == "status" else subscription_details(params) if method == "subscription" else enqueue(params) if method == "action" else {"ok": False, "error": "Unknown method."}
        else:
            result = {"ok": False, "error": "Use the NARA page in LuCI."}
    except NavaError as exc:
        result = {"ok": False, "error": str(exc)}
    except Exception:
        result = {"ok": False, "error": "Invalid request or system unavailable."}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
