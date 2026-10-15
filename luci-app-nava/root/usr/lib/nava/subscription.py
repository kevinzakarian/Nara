"""Subscription conversion. No remote converter and no executable configuration."""
import base64
import copy
import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 1000


class NavaError(Exception):
    pass


def decode64(value):
    value = re.sub(r"\s+", "", value)
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8-sig")
    except (ValueError, UnicodeError):
        raise NavaError("Invalid Base64 subscription or credentials.") from None


def port(value):
    try:
        result = int(value)
    except (ValueError, TypeError):
        raise NavaError("Missing or invalid server port.") from None
    if isinstance(value, bool) or not 1 <= result <= 65535:
        raise NavaError("Server port must be between 1 and 65535.")
    return result


def host(value):
    if not isinstance(value, str) or not value or len(value) > 253 or re.search(r"[\s/@\\\x00-\x1f]", value):
        raise NavaError("Invalid server address.")
    return value


def valid_uuid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise NavaError("Invalid UUID.") from None


def tls_options(q, server, default=False):
    security = q.get("security", "tls" if default else "none")
    if security not in ("none", "", "tls", "reality"):
        raise NavaError("Unsupported TLS security mode.")
    if security in ("none", ""):
        return None
    tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or server}
    if q.get("allowInsecure", q.get("insecure", "0")).lower() in ("1", "true"):
        tls["insecure"] = True
    if q.get("alpn"):
        tls["alpn"] = q["alpn"].split(",")
    if q.get("fp") or security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": q.get("fp") or "chrome"}
    if security == "reality":
        if not q.get("pbk"):
            raise NavaError("Reality public key is missing.")
        tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
    return tls


def transport_options(q):
    kind = q.get("type", "tcp")
    if kind in ("tcp", "raw", "none", ""):
        if q.get("headerType", "none") != "none":
            raise NavaError("TCP header camouflage is not supported by sing-box.")
        return None
    if kind == "ws":
        transport = {"type": "ws", "path": q.get("path", "/")}
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}
        # v2rayN's ?ed= convention is a transport option, not part of the WS path.
        p = urlsplit(transport["path"])
        early = parse_qs(p.query).get("ed", [None])[0]
        if early is not None:
            try:
                transport["max_early_data"] = int(early)
            except ValueError:
                raise NavaError("Invalid WebSocket early data.") from None
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            transport["path"] = p.path or "/"
        return transport
    if kind == "grpc":
        if q.get("mode", "gun") not in ("gun", ""):
            raise NavaError("gRPC multi mode is not supported.")
        return {"type": "grpc", "service_name": q.get("serviceName", q.get("path", ""))}
    if kind in ("http", "h2"):
        result = {"type": "http", "path": q.get("path", "/")}
        if q.get("host"):
            result["host"] = q["host"].split(",")
        return result
    if kind == "httpupgrade":
        return {"type": "httpupgrade", "path": q.get("path", "/"), "host": q.get("host", "")}
    raise NavaError("Unsupported transport (for example XHTTP, KCP or QUIC). Request a sing-box compatible node.")


def uri_node(line):
    if line.startswith("vmess://"):
        try:
            v = json.loads(decode64(line[8:].split("#", 1)[0]))
            server = host(v.get("add"))
            node = {"type": "vmess", "server": server, "server_port": port(v.get("port")),
                    "uuid": valid_uuid(v.get("id")), "security": v.get("scy") or "auto", "alter_id": int(v.get("aid") or 0)}
            q = {"type": v.get("net") or "tcp", "path": v.get("path") or "/", "host": v.get("host") or "",
                 "security": v.get("tls") or "none", "sni": v.get("sni") or "", "fp": v.get("fp") or ""}
            if q["type"] == "grpc":
                q["serviceName"] = v.get("path") or ""
            if q["type"] == "tcp":
                q["headerType"] = v.get("type") or "none"
            if v.get("alpn"):
                q["alpn"] = v["alpn"]
            tls, transport = tls_options(q, server), transport_options(q)
            if tls:
                node["tls"] = tls
            if transport:
                node["transport"] = transport
            return node, str(v.get("ps") or server)
        except (ValueError, TypeError, AttributeError, KeyError):
            raise NavaError("Invalid VMess JSON link.") from None
    if line.startswith("ss://"):
        query = line.split("?", 1)[1].split("#", 1)[0] if "?" in line else ""
        if parse_qs(query).get("plugin"):
            raise NavaError("Shadowsocks plugins require external executables and are not supported.")
        raw = line[5:].split("#", 1)[0].split("?", 1)[0].rstrip("/")
        if "@" not in raw:
            line = "ss://" + decode64(raw) + ("#" + line.split("#", 1)[1] if "#" in line else "")
    try:
        u = urlsplit(line)
        kind = {"ss": "shadowsocks", "hy2": "hysteria2"}.get(u.scheme, u.scheme)
        if kind not in ("vless", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls"):
            raise NavaError("Unsupported subscription protocol.")
        server = host(u.hostname)
        node = {"type": kind, "server": server, "server_port": port(u.port or (443 if kind in ("hysteria2", "tuic", "anytls", "trojan") else None))}
        q = {k: v[-1] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        username, password = unquote(u.username or ""), unquote(u.password or "")
        if kind == "shadowsocks":
            auth = unquote(u.netloc.rsplit("@", 1)[0])
            if ":" not in auth:
                auth = decode64(auth)
            if ":" not in auth:
                raise NavaError("Invalid Shadowsocks credentials.")
            node["method"], node["password"] = auth.split(":", 1)
            if q.get("plugin"):
                raise NavaError("Shadowsocks plugins require external executables and are not supported.")
        elif kind in ("vless", "tuic"):
            node["uuid"] = valid_uuid(username)
            if kind == "tuic":
                node["password"] = password
                node["congestion_control"] = q.get("congestion_control", "cubic")
                node["udp_relay_mode"] = q.get("udp_relay_mode", "native")
            elif q.get("flow"):
                node["flow"] = q["flow"]
            if kind == "vless" and q.get("encryption", "none") != "none":
                raise NavaError("This VLESS encryption mode is not supported.")
        else:
            node["password"] = username + (":" + password if u.password is not None else "")
        if kind != "shadowsocks":
            tls = tls_options(q, server, default=kind != "vless")
            if tls:
                node["tls"] = tls
        if kind in ("vless", "trojan"):
            transport = transport_options(q)
            if transport:
                node["transport"] = transport
        if kind == "hysteria2":
            if q.get("obfs"):
                if q["obfs"] != "salamander" or not q.get("obfs-password"):
                    raise NavaError("Invalid Hysteria2 obfuscation options.")
                node["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
            if q.get("mport"):
                node["server_ports"] = [p.replace("-", ":") for p in q["mport"].split(",")]
                node.pop("server_port")
        return node, unquote(u.fragment) or server
    except (ValueError, TypeError, AttributeError):
        raise NavaError("Invalid server link.") from None


PROTOCOL_FIELDS = {
    "vless": {"uuid", "flow", "packet_encoding"},
    "vmess": {"uuid", "security", "alter_id", "global_padding", "authenticated_length", "packet_encoding"},
    "trojan": {"password"}, "shadowsocks": {"method", "password", "udp_over_tcp"},
    "hysteria2": {"password", "up_mbps", "down_mbps", "obfs", "server_ports", "hop_interval"},
    "tuic": {"uuid", "password", "congestion_control", "udp_relay_mode", "zero_rtt_handshake", "heartbeat"},
    "anytls": {"password", "idle_session_check_interval", "idle_session_timeout", "min_idle_session"},
    "socks": {"version", "username", "password", "udp_over_tcp"},
    "http": {"username", "password", "path", "headers"},
}
COMMON_FIELDS = {"type", "tag", "server", "server_port", "tls", "transport", "multiplex", "network", "connect_timeout", "tcp_fast_open", "domain_resolver"}


def native_node(value):
    if not isinstance(value, dict):
        raise NavaError("Each outbound must be an object.")
    kind = value.get("type")
    if not isinstance(kind, str):
        raise NavaError("Outbound type must be a string.")
    if kind in ("direct", "block", "dns", "selector", "urltest"):
        return None
    if kind not in PROTOCOL_FIELDS:
        raise NavaError("Unsupported outbound type in sing-box JSON.")
    if set(value) - COMMON_FIELDS - PROTOCOL_FIELDS[kind]:
        raise NavaError("Outbound has unsupported options, external files, plugins or routing dependencies.")
    def validate_nested(obj):
        if isinstance(obj, dict):
            for key, child in obj.items():
                if key.endswith("_path") or key in ("path", "command", "detour", "certificate_provider"):
                    # Only a transport/HTTP URL path is allowed, checked outside this walk.
                    raise NavaError("External files and executable options are not allowed in subscriptions.")
                validate_nested(child)
        elif isinstance(obj, list):
            for child in obj:
                validate_nested(child)
    for key in ("tls", "multiplex", "obfs", "udp_over_tcp"):
        if key in value and not isinstance(value[key], dict) and not (key == "udp_over_tcp" and isinstance(value[key], bool)):
            raise NavaError("Invalid nested outbound options.")
        validate_nested(value.get(key))
    transport = value.get("transport")
    if transport:
        if not isinstance(transport, dict) or transport.get("type") not in ("ws", "grpc", "http", "httpupgrade"):
            raise NavaError("Unsupported native transport.")
        validate_nested({k: v for k, v in transport.items() if k != "path"})
    node = copy.deepcopy(value)
    name = str(node.pop("tag", "") or node.get("server", kind))
    node["server"] = host(node.get("server"))
    if "server_ports" not in node:
        node["server_port"] = port(node.get("server_port"))
    if kind in ("vless", "vmess", "tuic"):
        node["uuid"] = valid_uuid(node.get("uuid"))
    return node, name


def parse_subscription(content):
    nodes, warnings, _ = parse_subscription_bundle(content)
    return nodes, warnings


def _subscription_dns(data):
    """Validate inline DNS without changing the provider's choices or rules."""
    if not isinstance(data, dict) or "dns" not in data:
        return None, []
    raw = data["dns"]
    if not isinstance(raw, dict) or not isinstance(raw.get("servers", []), list):
        raise NavaError("Subscription DNS must be an object with a servers array.")
    if len(raw.get("servers", [])) > 32:
        raise NavaError("Subscription contains too many DNS servers.")
    def check_inline(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"command", "certificate_provider"} or (key.endswith("_path") and key not in {"process_path", "process_path_regex"}):
                    raise NavaError("Subscription DNS requires external files or services. Request an inline DNS configuration.")
                check_inline(child)
        elif isinstance(value, list):
            for child in value:
                check_inline(child)
    check_inline(raw)
    for server in raw.get("servers", []):
        if isinstance(server, dict) and "path" in server and server.get("type") not in {"https", "http3", "h3"}:
            raise NavaError("Subscription DNS cannot read external files.")
    return copy.deepcopy(raw), []


def dns_rule_set_references(dns):
    """Collect rule-set references, including nested logical DNS rules."""
    references = set()
    def walk(value):
        if isinstance(value, dict):
            tags = value.get("rule_set", [])
            if isinstance(tags, str):
                tags = [tags]
            if isinstance(tags, list):
                references.update(tag for tag in tags if isinstance(tag, str))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    if isinstance(dns, dict):
        walk(dns.get("rules", []))
    return references


def _subscription_dns_context(data, nodes):
    """Retain dependencies required by the subscription's unchanged DNS rules."""
    if not isinstance(data, dict) or not isinstance(data.get("dns"), dict):
        return {}
    context = {"outbounds": [], "rule_sets_retained": True}
    route = data.get("route", {})
    if isinstance(route, dict) and "default_domain_resolver" in route:
        context["domain_resolver"] = copy.deepcopy(route["default_domain_resolver"])
    leaves = {n.get("source_tag"): n["id"] for n in nodes if n.get("source_tag")}
    originals = {o["tag"]: o for o in data.get("outbounds", []) if isinstance(o, dict) and isinstance(o.get("tag"), str)}
    added, visiting = set(), set()
    # Different source tags may point at identical leaves, deduplicated above.
    for tag, original in originals.items():
        try:
            parsed = native_node(original)
            if parsed:
                ident = "node-" + hashlib.sha256(json.dumps(parsed[0], sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
                if any(n["id"] == ident for n in nodes):
                    leaves[tag] = ident
        except NavaError:
            pass
    def retain(tag):
        if tag in {"proxy", "auto", "direct"} or tag in added or any(n["id"] == tag for n in nodes):
            return
        if tag in visiting or tag not in originals:
            raise NavaError("Subscription DNS has an unresolved outbound dependency. Choose a DNS override or ask the provider for a compatible configuration.")
        visiting.add(tag)
        source = originals[tag]
        if tag in leaves:
            outbound = {"type": "selector", "tag": tag, "outbounds": [leaves[tag]], "default": leaves[tag]}
        elif source.get("type") == "direct":
            outbound = {"type": "direct", "tag": tag}
        elif source.get("type") in {"selector", "urltest"}:
            allowed = {"type", "tag", "outbounds", "default", "url", "interval", "tolerance", "idle_timeout", "interrupt_exist_connections"}
            if set(source) - allowed or not isinstance(source.get("outbounds"), list) or not all(isinstance(t, str) for t in source["outbounds"]):
                raise NavaError("Subscription DNS depends on an unsupported outbound group. Choose a DNS override.")
            outbound = copy.deepcopy(source)
            for child in outbound["outbounds"]:
                retain(child)
        else:
            raise NavaError("Subscription DNS depends on an unsupported outbound. Choose a DNS override.")
        visiting.remove(tag)
        added.add(tag)
        context["outbounds"].append(outbound)
    try:
        for server in data["dns"].get("servers", []):
            if isinstance(server, dict) and isinstance(server.get("detour"), str) and server["detour"]:
                retain(server["detour"])
        required = dns_rule_set_references(data["dns"])
        definitions = route.get("rule_set", []) if isinstance(route, dict) else []
        if not isinstance(definitions, list):
            raise NavaError("Subscription DNS has invalid rule-set definitions. Update the subscription or choose a DNS override.")
        retained, found = [], set()
        clients = {item["tag"]: item for item in (data.get("http_clients") or [])
                   if isinstance(item, dict) and isinstance(item.get("tag"), str)}
        needed_clients = {}
        def check_files(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"path", "command", "certificate_provider"} or (key.endswith("_path") and key not in {"process_path", "process_path_regex"}):
                        raise NavaError("Subscription DNS rule sets require external files or services. Choose a DNS override or request remote or inline rule sets.")
                    check_files(child)
            elif isinstance(value, list):
                for child in value:
                    check_files(child)
        for definition in definitions:
            if not isinstance(definition, dict):
                continue
            tag = definition.get("tag")
            tags = [tag] if isinstance(tag, str) else tag if isinstance(tag, list) else []
            matched = [tag for tag in tags if isinstance(tag, str) and tag in required]
            if not matched:
                continue
            item = copy.deepcopy(definition)
            check_files(item)
            if isinstance(item.get("tag"), list):
                item["tag"] = matched
            retained.append(item)
            found.update(matched)
            if isinstance(item.get("download_detour"), str) and item["download_detour"]:
                retain(item["download_detour"])
            if item.get("type") == "remote":
                url = item.get("url")
                try:
                    parsed_url = urlsplit(url) if isinstance(url, str) else None
                    valid_url = (parsed_url and parsed_url.scheme in {"http", "https"} and parsed_url.hostname
                                 and not parsed_url.username and not parsed_url.password
                                 and not re.search(r"[\s\x00-\x1f]", url))
                except ValueError:
                    valid_url = False
                if not valid_url:
                    raise NavaError("Subscription DNS has an invalid rule-set download URL. Choose a DNS override or request a compatible subscription.")
                client = item.get("http_client")
                if not client and not item.get("download_detour"):
                    client = data.get("default_http_client") or next(iter(clients), None)
                    if client:
                        item["http_client"] = client
                if isinstance(client, str) and client:
                    if client not in clients:
                        raise NavaError("Subscription DNS references a missing HTTP client. Update the subscription or choose a DNS override.")
                    needed_clients[client] = copy.deepcopy(clients[client])
                    client = clients[client]
                check_files(client)
                if isinstance(client, dict) and isinstance(client.get("detour"), str) and client["detour"]:
                    retain(client["detour"])
        if required - found:
            raise NavaError("Subscription DNS references a missing rule set. Update the subscription or choose a DNS override.")
        if retained:
            context["rule_set"] = retained
        if needed_clients:
            context["http_clients"] = list(needed_clients.values())
    except NavaError as exc:
        return {"error": str(exc), "rule_sets_retained": True}
    return context


def parse_subscription_bundle(content, include_context=False):
    if isinstance(content, bytes):
        if len(content) > MAX_BYTES:
            raise NavaError("Subscription exceeds 8 MiB.")
        try:
            content = content.decode("utf-8-sig")
        except UnicodeError:
            raise NavaError("Subscription is not UTF-8 text.") from None
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES:
        raise NavaError("Subscription exceeds 8 MiB.")
    content = content.strip()
    if not content:
        raise NavaError("Subscription is empty.")
    if not content.startswith(("{", "[")) and "://" not in content:
        if re.search(r"(^|\n)\s*(proxies|proxy-providers|mixed-port):", content):
            raise NavaError("Clash YAML is not supported. Request sing-box JSON or V2Ray/Base64 subscription format.")
        content = decode64(content).strip()
    warnings, parsed, subscription_dns, data = [], [], None, None
    if content.startswith(("{", "[")):
        try:
            data = json.loads(content)
        except ValueError:
            raise NavaError("Subscription contains invalid JSON.") from None
        values = data.get("outbounds") if isinstance(data, dict) else data
        if not isinstance(values, list):
            raise NavaError("Expected a sing-box outbounds array.")
        if isinstance(data, dict):
            subscription_dns, dns_warnings = _subscription_dns(data)
            warnings.extend(dns_warnings)
        parser = native_node
    else:
        values = [line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        parser = uri_node
    if len(values) > MAX_NODES:
        raise NavaError("Subscription contains more than 1000 entries.")
    seen = set()
    for index, value in enumerate(values, 1):
        try:
            item = parser(value)
            if item is None:
                continue
            node, name = item
            ident = "node-" + hashlib.sha256(json.dumps(node, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
            if ident in seen:
                continue
            seen.add(ident)
            node["tag"] = ident
            entry = {"id": ident, "name": re.sub(r"[\x00-\x1f\x7f]", "", name)[:160], "outbound": node}
            if isinstance(value, dict) and isinstance(value.get("tag"), str):
                entry["source_tag"] = value["tag"]
            parsed.append(entry)
        except NavaError as exc:
            warnings.append("Entry %d: %s" % (index, exc))
    if not parsed:
        raise NavaError("No supported servers found. " + (warnings[0] if warnings else ""))
    result = (parsed, warnings, subscription_dns)
    return (*result, _subscription_dns_context(data, parsed)) if include_context else result


DNS_HTTPS_HOSTS = {
    "1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
    "8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
    "208.67.222.222": "doh.opendns.com", "208.67.220.220": "doh.opendns.com",
    "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
    "94.140.14.14": "dns.adguard-dns.com", "94.140.15.15": "dns.adguard-dns.com",
}


def _https_dns(address, tag, server_name):
    return {"type": "https", "tag": tag, "server": address, "path": "/dns-query",
            "tls": {"enabled": True, "server_name": server_name}, "detour": "proxy"}


def _custom_dns_servers(custom_dns):
    if not isinstance(custom_dns, str) or not custom_dns.strip():
        raise NavaError("Enter one or more custom DNS server addresses.")
    values = [value.strip() for value in custom_dns.split(",") if value.strip()]
    if not 1 <= len(values) <= 8:
        raise NavaError("Custom DNS supports 1 to 8 comma-separated servers.")
    servers = []
    for index, value in enumerate(values, 1):
        server = {"type": "tcp", "tag": "custom-dns-%d" % index, "detour": "proxy"}
        try:
            ipaddress.ip_address(value)
            server["server"] = value
            if value in DNS_HTTPS_HOSTS:
                server = _https_dns(value, server["tag"], DNS_HTTPS_HOSTS[value])
        except ValueError:
            try:
                parsed = urlsplit(value if "://" in value else "tcp://" + value)
                if parsed.scheme not in {"udp", "tcp", "tls", "https", "quic"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                    raise ValueError()
                server.update(type=parsed.scheme, server=host(parsed.hostname))
                if parsed.port is not None:
                    server["server_port"] = port(parsed.port)
                if parsed.scheme == "https":
                    server["path"] = (parsed.path or "/dns-query") + ("?" + parsed.query if parsed.query else "")
                elif parsed.path or parsed.query:
                    raise ValueError()
                if parsed.scheme in {"tls", "https", "quic"}:
                    server["tls"] = {"enabled": True, "server_name": parsed.hostname}
            except (ValueError, NavaError):
                raise NavaError("Invalid custom DNS address. Use an IP, hostname or udp://, tcp://, tls://, https:// or quic:// URL.") from None
        if re.search(r"[\s\\\x00-\x1f\x7f]", value) or len(value) > 2048:
            raise NavaError("Invalid custom DNS server address.")
        servers.append(server)
    return servers


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _dns_options(mode, custom_dns, subscription_dns, ipv6):
    mode = mode or "default"
    if mode == "default":
        return None
    presets = {
        "cloudflare": ("1.1.1.1", "cloudflare-dns.com"),
        "google": ("8.8.8.8", "dns.google"),
        "opendns": ("208.67.222.222", "doh.opendns.com")
    }
    if mode == "custom":
        servers = _custom_dns_servers(custom_dns)
        # Resolve the proxy host before it can carry DNS traffic. Use a
        # configured resolver directly; never substitute a public provider.
        bootstrap = copy.deepcopy(next((s for s in servers if _is_ip(s["server"])), servers[0]))
        bootstrap.pop("detour", None)
        bootstrap["tag"] = "bootstrap"
        # Bare provider IPs compile exactly like the preset: direct UDP
        # bootstrap plus verified HTTPS through the chosen proxy.
        bare_values = [v.strip() for v in custom_dns.split(",")]
        if bootstrap["server"] in bare_values and bootstrap["server"] in DNS_HTTPS_HOSTS:
            bootstrap = {"type": "udp", "tag": "bootstrap", "server": bootstrap["server"]}
        extra = []
        if not _is_ip(bootstrap["server"]):
            extra.append({"type": "local", "tag": "system-dns"})
            bootstrap["domain_resolver"] = "system-dns"
        for server in servers:
            if not _is_ip(server["server"]):
                server["domain_resolver"] = "bootstrap"
        return {"servers": [bootstrap] + extra + servers, "final": servers[0]["tag"], "strategy": "prefer_ipv4" if ipv6 else "ipv4_only"}
    if mode not in presets:
        raise NavaError("Invalid DNS selection.")
    address, server_name = presets[mode]
    return {"servers": [
        {"type": "udp", "tag": "bootstrap", "server": address},
        _https_dns(address, "remote-dns", server_name)
    ], "final": "remote-dns", "strategy": "prefer_ipv4" if ipv6 else "ipv4_only"}


def build_config(nodes, selected="auto", ipv6=True, dns_mode="default", custom_dns="", subscription_dns=None, subscription_context=None):
    if not nodes:
        raise NavaError("No servers are available.")
    ids = [n["id"] for n in nodes]
    if selected != "auto" and selected not in ids:
        raise NavaError("Selected server is no longer in the subscription. Select automatic mode.")
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "nava0", "address": ["198.18.0.1/30", "fdfe:dcba:9876::1/126"],
             "mtu": 1500, "auto_route": True, "auto_redirect": True, "strict_route": True,
             "iproute2_table_index": 20220, "iproute2_rule_index": 20220,
             "auto_redirect_iproute2_fallback_rule_index": 42020,
             "auto_redirect_input_mark": "0x6e01", "auto_redirect_output_mark": "0x6e02",
             "auto_redirect_reset_mark": "0x6e03", "auto_redirect_nfqueue": 20220,
             "route_exclude_address": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]},
            {"type": "mixed", "tag": "health-in", "listen": "127.0.0.1", "listen_port": 2080}
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + ids, "default": selected},
            {"type": "urltest", "tag": "auto", "outbounds": ids, "url": "https://www.gstatic.com/generate_204",
             "interval": "3m", "tolerance": 50},
            {"type": "direct", "tag": "direct"}
        ] + [copy.deepcopy(n["outbound"]) for n in nodes],
        "route": {"auto_detect_interface": True, "final": "proxy", "rules": [
            *([] if ipv6 else [{"ip_version": 6, "action": "reject"}]),
            {"ip_is_private": True, "action": "route", "outbound": "direct"}
        ]}
    }

    dns = _dns_options(dns_mode, custom_dns, subscription_dns, ipv6)
    default_dns = dns_mode in {"default", None, ""}
    use_dns_engine = not default_dns
    if dns is not None:
        config["dns"] = dns
    if default_dns:
        # Disable the core's implicit native DNS hijack while leaving its
        # ordinary system defaults alone. Import no subscription DNS engine,
        # resolver references, download clients or DNS-only outbounds.
        config["inbounds"][0]["dns_mode"] = "disabled"
        for outbound in config["outbounds"]:
            outbound.pop("domain_resolver", None)
    else:
        config["route"]["default_domain_resolver"] = "bootstrap"
        for outbound in config["outbounds"]:
            if "domain_resolver" in outbound:
                outbound["domain_resolver"] = "bootstrap"
    if use_dns_engine:
        # Only explicit DNS providers opt in to interception and temporary
        # router dnsmasq forwarding. Default never installs this listener.
        config["inbounds"].append({"type": "direct", "tag": "nava-dns-in", "listen": "127.0.0.1",
                                   "listen_port": 15353, "override_port": 53})
        config["route"]["rules"].insert(0, {"port": 53, "action": "hijack-dns"})
    return config
