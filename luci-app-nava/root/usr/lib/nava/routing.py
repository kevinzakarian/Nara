"""Country lists, staged and checked before a live configuration can use them."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from subscription import NavaError

SOURCES = {
    "ir": {"name": "Iran", "provider": "Chocolate4U", "repository": "https://github.com/Chocolate4U/Iran-sing-box-rules",
           "ip": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
           "domain": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs"},
    "cn": {"name": "China", "provider": "Loyalsoldier", "repository": "https://github.com/Loyalsoldier/v2ray-rules-dat",
           "ip": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/srs/cn.srs",
           "domain": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
    "ru": {"name": "Russia", "provider": "runetfreedom", "repository": "https://github.com/runetfreedom/russia-v2ray-rules-dat",
           "ip": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru.srs",
           "domain": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ru.srs"}
}
MAX_RULE_BYTES = 16 * 1024 * 1024
CUSTOM_FIELDS = {"direct_ips": ("Direct IP addresses", "ip"), "direct_domains": ("Direct domains", "domain"),
                 "vpn_ips": ("VPN IP addresses", "ip"), "vpn_domains": ("VPN domains", "domain")}
MAX_CUSTOM_BYTES = 8192
MAX_CUSTOM_ENTRIES = 256


def parse_custom(text, label, kind):
    if not isinstance(text, str):
        raise NavaError(label + " must be text, with one entry per line.")
    if len(text.encode("utf-8")) > MAX_CUSTOM_BYTES:
        raise NavaError(label + " is too long (maximum 8 KB per box).")
    values, seen = [], set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            if kind == "ip":
                if "%" in line:
                    raise ValueError()
                network = ipaddress.ip_network(line, strict=False)
                key = str(network)
                value = key if "/" in line else str(network.network_address)
            else:
                value = line.lower().rstrip(".")
                if value.startswith("*."):
                    value = value[2:]
                value = value.encode("idna").decode("ascii")
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    pass
                else:
                    raise ValueError()
                if (len(value) > 253 or not value or
                        any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split("."))):
                    raise ValueError()
                key = value
        except (ValueError, UnicodeError):
            expected = "an IP address or CIDR" if kind == "ip" else "a domain without a URL, port or path"
            raise NavaError("%s: line %d must contain %s." % (label, number, expected)) from None
        if key not in seen:
            seen.add(key); values.append(value)
        if len(values) > MAX_CUSTOM_ENTRIES:
            raise NavaError(label + " supports at most 256 entries.")
    return values


def custom_values(options):
    return {key: parse_custom(options.get(key, ""), *spec) for key, spec in CUSTOM_FIELDS.items()}


def validate_custom(options):
    return {key: "\n".join(values) for key, values in custom_values(options).items()}


def custom_rules(options):
    values = custom_values(options)
    rules = []
    # VPN wins over all explicit Direct entries and automatic country bypasses.
    for prefix, outbound in (("vpn", "proxy"), ("direct", "direct")):
        for suffix, field in (("ips", "ip_cidr"), ("domains", "domain_suffix")):
            entries = values[prefix + "_" + suffix]
            if entries:
                rules.append({field: entries, "action": "route", "outbound": outbound})
    return rules


def domain_list(content):
    """Translate Loyalsoldier's published direct list without broadening matches."""
    fields = {"domain": [], "domain_suffix": [], "domain_regex": [], "domain_keyword": []}
    prefixes = {"full": "domain", "domain": "domain_suffix", "regexp": "domain_regex", "keyword": "domain_keyword"}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            prefix, value = line.split(':', 1)
            if prefix not in prefixes or not value:
                raise NavaError("The China domain list contains an unsupported rule.")
            fields[prefixes[prefix]].append(value)
        else:
            if not re.fullmatch(r"[a-zA-Z0-9_.-]+", line):
                raise NavaError("The China domain list contains an invalid domain.")
            fields["domain_suffix"].append(line)
    rule = {key: sorted(set(values)) for key, values in fields.items() if values}
    if not rule:
        raise NavaError("The China domain list is empty.")
    return {"version": 3, "rules": [rule]}


def definitions(manifest):
    return [{"type": "local", "tag": "nava-%s" % key, "format": "binary", "path": item["path"]}
            for key, item in manifest.get("files", {}).items()]


def normalize(value):
    value = value if isinstance(value, dict) else {}
    return {"enabled": value.get("enabled") is True,
            "ip_source": value.get("ip_source") if isinstance(value.get("ip_source"), str) and value.get("ip_source") in SOURCES else "ir",
            "domain_source": value.get("domain_source") if isinstance(value.get("domain_source"), str) and value.get("domain_source") in SOURCES else "ir",
            **{key: value.get(key) if isinstance(value.get(key), str) else "" for key in CUSTOM_FIELDS}}


def owned_path(data, key, item):
    if not item:
        raise NavaError("Routing lists are missing. Use Update routing lists first.")
    path = Path(item.get("path", ""))
    base = (data / "routing-lists").resolve()
    if (path.name != key + ".srs" or not path.parent.name.startswith("generation-") or
            path.parent.parent.resolve() != base or path.is_symlink() or path.parent.is_symlink()):
        raise NavaError("Invalid routing list path. Update routing lists again.")
    if not path.is_file() or path.stat().st_size != item.get("bytes"):
        raise NavaError("Routing lists are missing or damaged. Use Update routing lists first.")
    return path


def selected(config, manifest, data):
    options = normalize(config.get("routing"))
    if not options["enabled"]:
        return None
    keys = [options["domain_source"] + "-domain", options["ip_source"] + "-ip"]
    files = manifest.get("files", {})
    for key in keys:
        item = files.get(key, {})
        path = owned_path(data, key, item)
        if hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
            raise NavaError("Routing lists failed integrity validation. Update routing lists again.")
    return {"rule_set": definitions({"files": {key: files[key] for key in keys}}),
            "rules": [{"type": "logical", "mode": "and", "rules": [
                {"rule_set": ["nava-" + key]},
                # A country list classifies resolver IPs too. Do not let it
                # move DNS off the base VPN path (UDP/TCP 53, DoT/DoQ 853).
                # This selects no resolver and adds no DNS engine or hijack.
                {"port": [53, 853], "invert": True}],
                "action": "route", "outbound": "direct"} for key in keys]}


def apply(generated, config, manifest, data):
    options = normalize(config.get("routing"))
    custom = custom_rules(options)
    country = selected(config, manifest, data)
    if not country and not custom:
        return generated
    route = generated["route"]
    if country:
        route["rule_set"] = route.get("rule_set", []) + country["rule_set"]
    # Keep the explicit DNS provider, IPv6 setting and private LAN access ahead
    # of routing exceptions. No new resolver, DNS hijack or kernel exclusions.
    route["rules"].extend([
        {"inbound": ["health-in"], "action": "route", "outbound": "proxy"},
        {"inbound": ["tun-in"], "action": "sniff", "sniffer": ["http", "tls", "quic"], "timeout": "300ms"},
        *custom,
        *(country["rules"] if country else [])])
    return generated


def summary(manifest, data):
    files = manifest.get("files", {})
    available = {}
    for key in (country + "-" + kind for country in SOURCES for kind in ("ip", "domain")):
        try:
            owned_path(data, key, files.get(key, {}))
            available[key] = True
        except NavaError:
            available[key] = False
    return {"updated": manifest.get("updated"), "available": available}


def stage(data, core, download, command, check_config, progress):
    """All six files form one generation; no active list is overwritten."""
    base = data / "routing-lists"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix="generation-", dir=str(base)))
    manifest = {"updated": int(time.time()), "files": {}}
    try:
        for country, source in SOURCES.items():
            for kind in ("ip", "domain"):
                key = country + "-" + kind
                progress("routing", "Updating %s %s list…" % (source["name"], kind))
                path = directory / (key + ".srs")
                if country == "cn" and kind == "domain":
                    raw = directory / "cn-domain.txt"
                    download(source[kind], raw, limit=MAX_RULE_BYTES, label="China domain routing list download")
                    original = raw.read_bytes()
                    rules = directory / "cn-domain.json"
                    rules.write_text(json.dumps(domain_list(original.decode('utf-8'))))
                    result = command([str(core), "rule-set", "compile", str(rules), "--output", str(path)],
                                     timeout=60, label="China domain list compilation")
                    if result.returncode:
                        raise NavaError("sing-box could not compile the China domain list.")
                    raw.unlink()
                    rules.unlink()
                else:
                    download(source[kind], path, limit=MAX_RULE_BYTES, label="%s %s routing list download" % (source["name"], kind))
                    original = path.read_bytes()
                if not path.is_file() or not path.stat().st_size or path.stat().st_size > MAX_RULE_BYTES:
                    raise NavaError("Invalid routing list size.")
                path.chmod(0o600)
                manifest["files"][key] = {"path": str(path), "url": source[kind],
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "source_sha256": hashlib.sha256(original).hexdigest(), "bytes": path.stat().st_size}
        candidate = directory / "check.json"
        candidate.write_text(json.dumps({"outbounds": [{"type": "direct", "tag": "direct"}],
                                         "route": {"rule_set": definitions(manifest), "final": "direct"}}))
        check_config(core, candidate)
        candidate.unlink()
        return manifest
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def prune(data, manifest):
    """Retain current metadata and any generation still referenced by the tunnel."""
    protected = {Path(item["path"]).parent for item in manifest.get("files", {}).values()}
    try:
        config = json.loads((data / "config.json").read_text())
        protected.update(Path(item["path"]).parent for item in config.get("route", {}).get("rule_set", []) if item.get("path"))
    except (OSError, ValueError):
        pass
    for directory in (data / "routing-lists").glob("generation-*"):
        if directory.is_dir() and not directory.is_symlink() and directory not in protected:
            shutil.rmtree(directory, ignore_errors=True)
