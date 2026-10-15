#!/usr/bin/env python3
"""Read-only routing diagnosis. Never print subscription URLs or credentials."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def query(args):
    try:
        result = subprocess.run(ip_command(args), capture_output=True, text=True, timeout=10)
        if result.returncode:
            return None
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def references_tun(value):
    if isinstance(value, dict):
        return any(references_tun(child) for child in value.values())
    if isinstance(value, list):
        return any(references_tun(child) for child in value)
    return value == 'nava0'


def stable_nft(value):
    """Ignore counters, handles and remaining element lifetime."""
    if isinstance(value, dict):
        return {key: (None if key == 'counter' else stable_nft(child))
                for key, child in value.items() if key not in ('handle', 'metainfo', 'expires')}
    if isinstance(value, list):
        return [stable_nft(child) for child in value]
    return value


def nft_summary(entries):
    summary = {}
    for name in ('fw4', 'passwall2', 'sing-box'):
        objects = [item for item in entries if any(isinstance(value, dict) and value.get('family') == 'inet'
                   and (value.get('table') == name or key == 'table' and value.get('name') == name)
                   for key, value in item.items())]
        summary[name] = {'present': bool(objects), 'rules': sum('rule' in item for item in objects),
                         'sets': sum('set' in item for item in objects),
                         'fingerprint': hashlib.sha256(json.dumps(stable_nft(objects), sort_keys=True).encode()).hexdigest()}
    return summary


def text_state(args):
    try:
        result = subprocess.run(ip_command(args), capture_output=True, text=True, timeout=10)
        return {'available': result.returncode == 0,
                'fingerprint': hashlib.sha256(result.stdout.encode()).hexdigest() if result.returncode == 0 else None}
    except (OSError, subprocess.TimeoutExpired):
        return {'available': False, 'fingerprint': None}


def file_fingerprint(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def ip_command(args):
    if args and args[0] == 'ip':
        for binary in ('/usr/libexec/ip-full', '/usr/sbin/ip-full', '/sbin/ip-full'):
            if Path(binary).is_file():
                return [binary, *args[1:]]
    return args


def country_rule(rule):
    if not isinstance(rule, dict):
        return False
    return (any(isinstance(tag, str) and tag.startswith('nava-') for tag in rule.get('rule_set', [])) or
            any(country_rule(child) for child in rule.get('rules', [])))


def report():
    preferences = read_json('/etc/nava/settings.json')
    runtime = read_json('/etc/nava/config.json')
    job = read_json('/var/run/nava/job.json')
    output = {'routing_enabled_saved': preferences.get('routing', {}).get('enabled', preferences.get('routing_enabled', False)),
              'autostart_saved': preferences.get('autostart'),
              'last_operation': {key: job.get(key) for key in ('action', 'state', 'stage', 'updated')},
              'cleanup_state': read_json('/var/run/nava/network-status.json').get('state', 'unknown'),
              'dns_forwarding_state': read_json('/var/run/nava/dns-status.json').get('state', 'unknown'),
              'conntrack_installed': bool(shutil.which('conntrack'))}
    try:
        source = Path('/usr/lib/nava/manager.py').read_bytes()
        version = re.search(rb'APP_VERSION\s*=\s*"([0-9.-]+)"', source)
        output['source_version'] = version.group(1).decode() if version else 'unknown'
        output['manager_sha256'] = hashlib.sha256(source).hexdigest()
        output['offline_save_guard_present'] = (b'if action == "save_routing" and not was_running:' in source or
                b'if action == "save_routing":' in source and b'if not running():' in source)
    except OSError:
        output['source_version'] = 'unavailable'
    try:
        package = subprocess.run(['opkg', 'list-installed', 'luci-app-nava'], capture_output=True, text=True, timeout=10)
        # Accept only the known package/version pattern, never arbitrary text.
        installed = re.search(r'^luci-app-nava - ([0-9.-]+)$', package.stdout.strip())
        output['installed_package_version'] = installed.group(1) if installed else 'unavailable'
    except (OSError, subprocess.TimeoutExpired):
        output['installed_package_version'] = 'unavailable'
    services = query(['ubus', 'call', 'service', 'list', '{}'])
    output['service_instances'] = {}
    if isinstance(services, dict):
        for name in ('nava', 'sing-box', 'passwall', 'passwall2', 'homeproxy', 'nikki', 'mihomo', 'clash', 'shadowsocksr'):
            if name not in services:
                continue
            instances = services[name].get('instances', {})
            # Number auxiliary instances rather than printing user-defined names.
            output['service_instances'][name] = [
                {'instance': key if name == 'nava' and key in ('core', 'dns') else index,
                 'running': bool(value.get('running')), 'pid': value.get('pid') if isinstance(value.get('pid'), int) else None}
                for index, (key, value) in enumerate(instances.items(), 1)]
    else:
        output['service_inspection'] = 'unavailable'
    core_count, other_count = 0, 0
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            words = path.read_bytes().split(b'\0')
            if Path(words[0].decode()).name == 'sing-box' and b'run' in words:
                if words[0] == b'/usr/lib/nava/core/sing-box' and b'/etc/nava/config.json' in words:
                    core_count += 1
                else:
                    other_count += 1
        except (OSError, UnicodeError):
            continue
    output['nava_core_process_count'] = core_count
    output['other_sing_box_process_count'] = other_count
    nft = query(['nft', '-j', 'list', 'ruleset'])
    if isinstance(nft, dict):
        entries = nft.get('nftables', [])
        output['sing_box_table_present'] = any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == 'sing-box' for item in entries)
        output['sing_box_rules_referencing_nava0'] = sum(1 for item in entries if item.get('rule', {}).get('table') == 'sing-box' and references_tun(item))
        output['fw4_rules_referencing_nava0'] = sum(1 for item in entries if item.get('rule', {}).get('table') == 'fw4' and references_tun(item))
        output['firewall_tables'] = nft_summary(entries)
    else:
        output['nft_inspection'] = 'unavailable'
    try:
        include = Path('/etc/nftables.d/0-sing-box-auto-redirect.nft').read_text()
        output['nava_firewall_include_present'] = 'nava0' in include
    except OSError:
        output['nava_firewall_include_present'] = False
    links = query(['ip', '-j', 'link', 'show'])
    output['tun_interface_present'] = any(link.get('ifname') == 'nava0' for link in links) if isinstance(links, list) else Path('/sys/class/net/nava0').exists()
    tun = next((item for item in runtime.get('inbounds', []) if item.get('type') == 'tun' and item.get('interface_name') == 'nava0'), {})
    output['runtime_tun'] = {key: tun.get(key) for key in ('auto_route', 'auto_redirect', 'iproute2_table_index', 'iproute2_rule_index')}
    output['runtime_country_rule_count'] = sum(country_rule(item) for item in runtime.get('route', {}).get('rules', []))
    output['route_state'] = {name: text_state(args) for name, args in {
        'ipv4_rules': ['ip', '-4', 'rule', 'show'], 'ipv6_rules': ['ip', '-6', 'rule', 'show'],
        'ipv4_routes': ['ip', '-4', 'route', 'show', 'table', 'all'],
        'ipv6_routes': ['ip', '-6', 'route', 'show', 'table', 'all']}.items()}
    output['configuration_fingerprints'] = {name: file_fingerprint(path) for name, path in {
        'nava_runtime': '/etc/nava/config.json', 'network': '/etc/config/network',
        'firewall': '/etc/config/firewall', 'dhcp': '/etc/config/dhcp', 'passwall2': '/etc/config/passwall2'}.items()}
    output['dnsmasq_configuration_fingerprints'] = sorted(filter(None,
        (file_fingerprint(path) for folder in ('/var/etc', '/tmp/etc') for path in Path(folder).glob('dnsmasq.conf.*'))))
    return output


def watch(timeout=90):
    before = report()
    initial_job = before['last_operation']
    print('Ready. While Nara is disconnected and direct Internet works, press Apply routing once. Waiting up to 90 seconds...', flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = read_json('/var/run/nava/job.json')
        if job.get('action') == 'save_routing' and job.get('updated') != initial_job.get('updated') and job.get('state') in ('done', 'error'):
            time.sleep(2)
            after = report()
            changes = [key for key in before if before.get(key) != after.get(key)]
            print(json.dumps({'changed_sections': changes, 'before': before, 'after': after}, indent=2), flush=True)
            return
        time.sleep(1)
    print(json.dumps({'error': 'No completed Apply routing operation observed before timeout.', 'before': before}, indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--watch']:
        watch()
    else:
        print(json.dumps(report(), indent=2))
