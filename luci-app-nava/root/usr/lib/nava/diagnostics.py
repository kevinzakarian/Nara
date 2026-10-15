"""Probe proxy endpoints and HTTPS through each server without changing Nava."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from subscription import NavaError, build_config

TARGETS = {
    'apple': ('Apple', 'https://www.apple.com/'),
    'cloudflare': ('Cloudflare', 'https://cp.cloudflare.com/generate_204'),
    'facebook': ('Facebook', 'https://www.facebook.com/'),
    'github': ('GitHub', 'https://github.com/'),
    'google': ('Google', 'https://www.gstatic.com/generate_204'),
    'instagram': ('Instagram', 'https://www.instagram.com/'),
    'microsoft': ('Microsoft', 'https://www.microsoft.com/'),
}


def wan_interface():
    from manager import command, DATA, read_json
    excluded = {'lo', 'nava0'} | {item.get('interface_name') for item in read_json(DATA / 'config.json', {}).get('inbounds', []) if item.get('type') == 'tun'}
    def usable(device):
        return isinstance(device, str) and device not in excluded and bool(re.fullmatch(r'[A-Za-z0-9_.:@-]{1,64}', device))
    def query(args):
        try:
            result = command(args, timeout=5)
            return result.stdout if result.returncode == 0 else ''
        except NavaError:
            return ''
    def decode(value):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    # netifd knows PPPoE and policy-routed WAN devices even when table main
    # has no default route. IPv4 defaults take precedence over IPv6 defaults.
    dump = decode(query(['ubus', 'call', 'network.interface', 'dump']))
    interfaces = dump.get('interface', []) if isinstance(dump, dict) else []
    if not isinstance(interfaces, list):
        interfaces = []
    interfaces = [item for item in interfaces if isinstance(item, dict)]
    candidates = []
    for item in interfaces:
        device = item.get('l3_device') or item.get('device')
        if not item.get('up') or not usable(device):
            continue
        for route in item.get('route', []):
            if route.get('target') in {'0.0.0.0', '::', 'default'} and str(route.get('mask', 0)) == '0':
                candidates.append((route.get('target') == '::', int(route.get('metric') or 0), device))
    if candidates:
        return min(candidates)[2]
    # Read all routing tables; tolerate ip builds without JSON support.
    for family in ('-4', '-6'):
        routes = decode(query(['ip', '-j', family, 'route', 'show', 'table', 'all']))
        if isinstance(routes, list):
            defaults = [item for item in routes if item.get('dst') in {'default', '0.0.0.0/0', '::/0'} and usable(item.get('dev'))]
            if defaults:
                return min(defaults, key=lambda item: int(item.get('metric') or 0))['dev']
        lines = query(['ip', family, 'route', 'show', 'table', 'all']).splitlines()
        for line in lines:
            match = re.search(r'^default\s.*\bdev\s+(\S+)', line)
            if match and usable(match[1]):
                return match[1]
    # A configured, up WAN is also usable with external policy routing.
    for item in interfaces:
        if item.get('interface') in {'wan', 'wan6', 'wan_6'} and item.get('up'):
            device = item.get('l3_device') or item.get('device')
            if usable(device):
                return device
    raise NavaError('No active WAN interface was found. Check the router Internet connection and retry.')


def endpoint(host, port):
    # Resolve first: numeric ping destinations cannot inject command options.
    try:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    except OSError:
        return None


def ping(address, interface):
    from manager import command
    if address is None:
        return {'state': 'dns_failed'}
    ip = address[4][0]
    args = ['ping'] + (['-6'] if ipaddress.ip_address(ip).version == 6 else [])
    try:
        result = command(args + ['-I', interface, '-c', '1', '-W', '2', ip], timeout=4, label='Ping')
    except NavaError:
        return {'state': 'unavailable'}
    match = re.search(r'time[=<]\s*([\d.]+)\s*ms', result.stdout)
    return {'state': 'ok', 'ms': round(float(match[1]), 1)} if result.returncode == 0 and match else {'state': 'no_reply'}


def tcping(address, interface, protocol):
    if protocol in {'hysteria2', 'tuic', 'hysteria'}:
        return {'state': 'not_applicable'}
    if address is None:
        return {'state': 'dns_failed'}
    family, kind, proto, _, destination = address
    try:
        with socket.socket(family, kind, proto) as connection:
            connection.settimeout(3)
            if hasattr(socket, 'SO_BINDTODEVICE'):
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
            start = time.monotonic()
            connection.connect(destination)
            return {'state': 'ok', 'ms': round((time.monotonic() - start) * 1000, 1)}
    except OSError:
        return {'state': 'failed'}


def isolated_config(cache, node_id, config, port, interface):
    from manager import prepare_dns_bootstrap
    result = build_config(cache['nodes'], node_id, config['ipv6'], config.get('dns_mode', 'default'),
                          config.get('custom_dns', ''), cache.get('dns'), cache.get('dns_context'))
    if config.get('dns_mode', 'default') != 'default':
        result = prepare_dns_bootstrap(result)
    result['inbounds'] = [{'type': 'mixed', 'tag': 'health-in', 'listen': '127.0.0.1', 'listen_port': port}]
    result['outbounds'][0].update(outbounds=[node_id], default=node_id)
    # Disable periodic tests. This process tests exactly one chosen server.
    result['outbounds'][1] = {'type': 'selector', 'tag': 'auto', 'outbounds': [node_id], 'default': node_id}
    result['route']['rules'] = [] if config['ipv6'] else [{'ip_version': 6, 'action': 'reject'}]
    result['route']['auto_detect_interface'] = False
    result['route']['default_interface'] = interface
    return result


def url_test(cache, node, config, target, interface):
    import manager as m
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='nava-test-', dir=str(m.RUN)) as directory:
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            candidate = isolated_config(cache, node['id'], config, port, interface)
            path = Path(directory) / 'config.json'
            m.atomic_json(path, candidate)
            process = subprocess.Popen([str(m.CORE), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                return {'state': 'core_failed'}
            # HEAD measures a verified HTTPS response, avoiding large page downloads.
            response = m.command(['curl', '-q', '--silent', '--head', '--output', '/dev/null',
                                  '--write-out', '%{http_code} %{time_total}', '--proxy', 'http://127.0.0.1:%d' % port,
                                  '--noproxy', '', '--connect-timeout', '5', '--max-time', '10', TARGETS[target][1]], timeout=12)
            parts = response.stdout.strip().split()
            if response.returncode or len(parts) != 2:
                return {'state': 'failed'}
            code, seconds = int(parts[0]), float(parts[1])
            return {'state': 'ok' if 200 <= code < 400 else 'restricted' if code in {401, 403, 429} else 'http_error',
                    'ms': round(seconds * 1000, 1), 'http_code': code}
    except (NavaError, OSError, ValueError):
        return {'state': 'failed'}
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def test_node(cache, node, config, target, interface):
    outbound = node['outbound']
    address = endpoint(outbound.get('server'), outbound.get('server_port', 443))
    return {'name': node['name'], 'ping': ping(address, interface),
            'tcping': tcping(address, interface, outbound['type']),
            'url_test': url_test(cache, node, config, target, interface)}


def aggregate(results, metric):
    values = [(item, item[metric]) for item in results]
    good = [(item, result) for item, result in values if result.get('state') == 'ok']
    reachable = [(item, result) for item, result in values if result.get('state') == 'restricted']
    winner = min(good or reachable, key=lambda pair: pair[1]['ms']) if good or reachable else None
    applicable = sum(result.get('state') != 'not_applicable' for _, result in values)
    summary = {'state': 'pending' if not values else 'not_applicable' if not applicable else 'failed',
               'passed': len(good), 'tested': len(values), 'applicable': applicable}
    if winner:
        summary.update(winner[1], server=winner[0]['name'])
    elif values and all(result.get('state') == 'no_reply' for _, result in values):
        summary['state'] = 'no_reply'
    return summary


def test_all(config):
    import manager as m
    target = config.pop('test_target', 'google')
    interface = wan_interface()
    results = m.read_json(m.DATA / 'tests.json', {})
    results.update(target=target)
    entries = results.setdefault('entries', {})
    for index, item in enumerate(config['subscriptions'], 1):
        scoped = {**config, 'active_subscription': item['id'], 'subscription_url': item['url']}
        cache = m.active_cache(scoped)
        source_hash = hashlib.sha256(item['url'].encode()).hexdigest()
        try:
            if not cache.get('nodes') or cache.get('source_hash') != source_hash:
                cache = m.fetch_subscription(scoped)
                m.save_cache(scoped, cache)
            nodes = cache['nodes']
            record = {'source_hash': source_hash, 'cache_updated': cache.get('updated'), 'target': target,
                      'target_label': TARGETS[target][0], 'target_url': TARGETS[target][1], 'total': len(nodes)}
            complete = []
            entries[item['id']] = record
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(test_node, cache, node, config, target, interface) for node in nodes]
                for future in as_completed(futures):
                    complete.append(future.result())
                    record.update({metric: aggregate(complete, metric) for metric in ('ping', 'tcping', 'url_test')})
                    record['checked'] = int(time.time())
                    m.atomic_json(m.DATA / 'tests.json', results)
                    m.job_update('tests', 'Subscription %d/%d · %d/%d servers tested against %s.' %
                                 (index, len(config['subscriptions']), len(complete), len(nodes), TARGETS[target][0]))
        except NavaError as exc:
            entries[item['id']] = {'source_hash': source_hash, 'cache_updated': cache.get('updated'),
                                   'target': target, 'error': str(exc), 'checked': int(time.time())}
            m.atomic_json(m.DATA / 'tests.json', results)
    return 'Subscription tests finished. Each row shows the best result per test; hover for details.'
