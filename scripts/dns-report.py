#!/usr/bin/env python3
"""Read-only router DNS summary; never print subscription or proxy credentials."""
import ipaddress
import json
import subprocess
import sys

DNS_TYPES = {'udp', 'tcp', 'tls', 'https', 'http3', 'quic', 'local', 'dhcp',
             'hosts', 'fakeip', 'resolved', 'tailscale', 'mdns'}


def dns_summary(value, outbounds):
    value = value if isinstance(value, dict) else {}
    servers = [server for server in value.get('servers', []) if isinstance(server, dict)]
    aliases = {server.get('tag'): index for index, server in enumerate(servers, 1) if isinstance(server.get('tag'), str)}
    outbound_types = {item.get('tag'): item.get('type') for item in outbounds if isinstance(item, dict) and isinstance(item.get('tag'), str)}
    def resolver_ref(tag):
        return aliases.get(tag, 'unknown') if isinstance(tag, str) else 'unknown'
    def endpoint(server):
        address = server.get('server', '')
        try:
            return str(ipaddress.ip_address(address))
        except ValueError:
            return '<hostname or legacy address>' if address or server.get('address') else '<system or virtual resolver>'
    def rule_summary(rule):
        result = {'server': resolver_ref(rule.get('server')),
                  'conditions': sorted(set(rule) & {'inbound', 'outbound', 'clash_mode', 'query_type', 'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'rule_set', 'network', 'ip_version', 'ip_is_private', 'invert', 'rules', 'type'})}
        if 'clash_mode' in rule:
            result['clash_mode'] = rule['clash_mode'] if rule['clash_mode'] in {'direct', 'global', 'rule', 'Direct', 'Global', 'Rule'} else '<other>'
        if 'domain_regex' in rule:
            values = rule['domain_regex'] if isinstance(rule['domain_regex'], list) else [rule['domain_regex']]
            result['regex_matches_all'] = any(value in ('.*', '^.*$', '.+') for value in values)
        if 'outbound' in rule:
            values = rule['outbound'] if isinstance(rule['outbound'], list) else [rule['outbound']]
            result['outbound_any'] = 'any' in values
        if 'query_type' in rule:
            values = rule['query_type'] if isinstance(rule['query_type'], list) else [rule['query_type']]
            result['query_type'] = [value for value in values if isinstance(value, int) or value in ('A', 'AAAA', 'HTTPS')]
        return result
    return {'server_count': len(servers), 'final_server': resolver_ref(value.get('final')) if value.get('final') else 'first server',
            'servers': [{'number': index, 'type': server.get('type') if server.get('type') in DNS_TYPES else '<legacy or unknown>',
                         'endpoint': endpoint(server), 'detour_type': outbound_types.get(server.get('detour'), 'unspecified')
                         if outbound_types.get(server.get('detour'), 'unspecified') in {'direct', 'selector', 'urltest', 'trojan', 'vless', 'vmess', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'unspecified'} else '<other>',
                         'domain_resolver': resolver_ref(server.get('domain_resolver')) if isinstance(server.get('domain_resolver'), str) else bool(server.get('domain_resolver'))}
                        for index, server in enumerate(servers, 1)],
            'rule_count': len(value.get('rules', [])),
            'rules': [rule_summary(rule) for rule in value.get('rules', []) if isinstance(rule, dict)],
            'rule_servers': [resolver_ref(rule.get('server')) for rule in value.get('rules', []) if isinstance(rule, dict) and 'server' in rule]}


def report(version, settings, cache, runtime, forwarding, core_version=None):
    outbounds = runtime.get('outbounds', [])
    tun = next((item for item in runtime.get('inbounds', []) if item.get('type') == 'tun'), {})
    return {'application_version': version, 'core_version': core_version, 'selected_dns': settings.get('dns_mode'),
            'routing_enabled': settings.get('routing', {}).get('enabled', settings.get('routing_enabled', False)),
            'subscription_dns': dns_summary(cache.get('dns'), outbounds),
            'runtime_dns': dns_summary(runtime.get('dns'), outbounds),
            'runtime_dns_defined': 'dns' in runtime,
            'default_dns_unconfigured': settings.get('dns_mode') == 'default' and 'dns' not in runtime and 'default_domain_resolver' not in runtime.get('route', {}),
            'dns_config_matches_subscription': cache.get('dns') == runtime.get('dns'),
            'dns_rules_match_subscription': (cache.get('dns') or {}).get('rules', []) == (runtime.get('dns') or {}).get('rules', []),
            'tun_dns_mode': tun.get('dns_mode', '<core default>'),
            'dns_listener_present': any(item.get('tag') == 'nava-dns-in' for item in runtime.get('inbounds', [])),
            'dns_hijack_rule_present': any(rule.get('action') == 'hijack-dns' for rule in runtime.get('route', {}).get('rules', [])),
            'dnsmasq_forwarding_state': forwarding.get('state', 'unknown')}


if __name__ == '__main__':
    sys.path.insert(0, '/usr/lib/nava')
    import manager as m
    preferences = m.settings()
    output = report(m.APP_VERSION, preferences, m.active_cache(preferences),
                            m.read_json(m.DATA / 'config.json', {}),
                            m.read_json(m.RUN / 'dns-status.json', {}),
                            m.read_json(m.DATA / 'core.json', {}).get('version'))
    output['network_cleanup_state'] = m.read_json(m.RUN / 'network-status.json', {}).get('state', 'unknown')
    try:
        import network_cleanup as network
        snapshot = network.read_command(['nft', '-j', 'list', 'ruleset'])
        table, rules = network.nft_resources(snapshot)
        output['nava_redirect_table_present'] = table
        output['nava_firewall_rule_count'] = len(rules)
        output['nava_core_process_count'] = len(network.core_pids())
        result = network.call(['ip', '-j', 'link', 'show', 'dev', 'nava0'])
        output['tun_interface_present'] = bool(json.loads(result.stdout)) if result.returncode == 0 else False
    except (ImportError, OSError, ValueError, m.NavaError, subprocess.TimeoutExpired):
        output['network_inspection'] = '<unavailable>'
    try:
        result = subprocess.run(['opkg', 'list-installed', 'luci-app-nava'], capture_output=True, text=True, timeout=10)
        output['installed_package'] = result.stdout.strip() if result.returncode == 0 else '<unavailable>'
    except (OSError, subprocess.TimeoutExpired):
        output['installed_package'] = '<unavailable>'
    print(json.dumps(output, indent=2))
