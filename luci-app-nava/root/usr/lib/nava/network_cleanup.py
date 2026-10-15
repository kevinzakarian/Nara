"""Remove only Nava's residual TUN resources after its core has exited."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from subscription import NavaError

RUN = Path('/var/run/nava')
CONFIG = Path('/etc/nava/config.json')
PROC = Path('/proc')
CORE = '/usr/lib/nava/core/sing-box'
FW4_INCLUDE = Path('/etc/nftables.d/0-sing-box-auto-redirect.nft')
INTERFACE = 'nava0'
COMMENT = '!sing-box: Accept traffic from tun'


def call(args):
    from manager import ip_command
    args = ip_command(args)
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise NavaError('Network cleanup could not run %s. Check the installed dependencies.' % args[0]) from None


def read_command(args):
    result = call(args)
    if result.returncode:
        raise NavaError('Cannot inspect the router network state with %s.' % args[0])
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise NavaError('Invalid network state from %s. No unverified rules were removed.' % args[0]) from None


def core_pids(other=False):
    pids = []
    for path in PROC.glob('[0-9]*/cmdline'):
        try:
            words = path.read_bytes().split(b'\0')
            executable = words[0].decode()
            if Path(executable).name != 'sing-box' or b'run' not in words:
                continue
            ours = executable == CORE and str(CONFIG).encode() in words
            if ours != other:
                pids.append(int(path.parent.name))
        except (OSError, ValueError, UnicodeError):
            continue
    return pids


def contains_interface(value):
    if isinstance(value, dict):
        return any(contains_interface(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_interface(child) for child in value)
    return value == INTERFACE


def nft_resources(document):
    own_table, fw4_rules = False, []
    for item in document.get('nftables', []):
        for kind, value in item.items():
            if not isinstance(value, dict):
                continue
            if value.get('family') == 'inet' and value.get('table') == 'sing-box' and contains_interface(value):
                own_table = True
            if kind == 'rule' and value.get('family') == 'inet' and value.get('table') == 'fw4' and value.get('chain') in {'input', 'forward'} and value.get('comment') == COMMENT and contains_interface(value) and isinstance(value.get('handle'), int):
                fw4_rules.append((value['chain'], value['handle']))
    return own_table, fw4_rules


def owns_include():
    try:
        content = FW4_INCLUDE.read_text()
    except OSError:
        return False
    return ('iifname "nava0"' in content or 'oifname "nava0"' in content) and COMMENT in content


def tun_options():
    from manager import read_json
    tun = next((item for item in read_json(CONFIG, {}).get('inbounds', []) if item.get('type') == 'tun' and item.get('interface_name') == INTERFACE), {})
    return {'table': tun.get('iproute2_table_index', 2022), 'priority': tun.get('iproute2_rule_index', 9000),
            'fallback': tun.get('auto_redirect_iproute2_fallback_rule_index', 32768),
            'marks': [tun.get('auto_redirect_input_mark', '0x2023'), tun.get('auto_redirect_output_mark', '0x2024'), tun.get('auto_redirect_reset_mark', '0x2025')]}


def begin_stop():
    from manager import atomic_json
    table, rules = nft_resources(read_command(['nft', '-j', 'list', 'ruleset']))
    atomic_json(RUN / 'network-stop.json', {'owned': table or bool(rules) or owns_include(), 'options': tun_options()})


def owns_rule(rule, options):
    """Exact rules emitted for this generated mark-mode TUN, not a range wipe."""
    priority, table_id = options['priority'], options['table']
    if rule.get('priority') == priority + 2:
        return rule.get('action') == 'nop' and 'fwmark' not in rule and 'table' not in rule
    try:
        mark = int(str(rule.get('fwmark', '')), 0)
        input_mark, output_mark = (int(str(value), 0) for value in options['marks'][:2])
    except ValueError:
        return False
    if rule.get('priority') == priority and rule.get('goto') == priority + 2:
        return mark == output_mark
    return str(rule.get('table')) == str(table_id) and (
        (rule.get('priority') == priority + 1 and mark == input_mark) or
        (rule.get('priority') == options['fallback'] and mark == output_mark and rule.get('not', False)))


def delete_connections(filters):
    result = call(['conntrack', *filters])
    # conntrack returns 1 for an empty deletion; actual errors remain visible.
    if result.returncode and '0 flow entries' not in result.stderr:
        raise NavaError('Could not clear Nava connection state. Check conntrack and retry disconnect.')


def cleanup():
    from manager import atomic_json, read_json
    # procd's delete request can return before SIGTERM cleanup finishes.
    deadline = time.monotonic() + 15
    while core_pids():
        if time.monotonic() >= deadline:
            raise NavaError('The Nava core is still stopping. Network rules were left intact; retry disconnect.')
        time.sleep(.2)
    if core_pids(other=True):
        raise NavaError('Another sing-box service is running. Shared network rules were left intact.')
    document = read_command(['nft', '-j', 'list', 'ruleset'])
    table, rules = nft_resources(document)
    include = owns_include()
    previous = read_json(RUN / 'network-stop.json', {})
    owned = table or bool(rules) or include or previous.get('owned', False)
    options = previous.get('options', tun_options())
    if owned:
        table_id, priority, fallback = options['table'], options['priority'], options['fallback']
        if not all(isinstance(value, int) and value > 0 for value in (table_id, priority, fallback)) or table_id in {253, 254, 255}:
            raise NavaError('Unexpected Nava route identifiers. Router routes were left intact.')
        if not all(re.fullmatch(r'0x[0-9a-fA-F]{1,8}', str(mark)) for mark in options['marks']):
            raise NavaError('Unexpected Nava connection mark. Connection state was left intact.')
    if table or include:
        present = any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == 'sing-box' for item in document.get('nftables', []))
        if present and call(['nft', 'delete', 'table', 'inet', 'sing-box']).returncode:
            raise NavaError('Could not remove the remaining Nava redirect table.')
    for chain, handle in rules:
        if call(['nft', 'delete', 'rule', 'inet', 'fw4', chain, 'handle', str(handle)]).returncode:
            raise NavaError('Could not remove a remaining Nava firewall rule.')
    if include:
        FW4_INCLUDE.unlink()
    if owned:
        links = read_command(['ip', '-j', 'link', 'show'])
        tunnel_present = any(link.get('ifname') == INTERFACE for link in links)
        for family in ('-4', '-6'):
            for rule in read_command(['ip', '-j', family, 'rule', 'show']):
                pref = rule.get('priority', -1)
                if owns_rule(rule, options):
                    args = ['ip', family, 'rule', 'delete', 'priority', str(pref)]
                    if rule.get('table') is not None:
                        args += ['table', str(rule['table'])]
                    if call(args).returncode:
                        raise NavaError('Could not remove a remaining Nava routing rule.')
            # Never flush main/default or another interface's routes.
            # A nonpersistent TUN disappears with its process; its interface
            # routes disappear too. ip rejects a dev filter for a gone link.
            if tunnel_present and call(['ip', family, 'route', 'flush', 'table', str(table_id), 'dev', INTERFACE]).returncode:
                raise NavaError('Could not remove remaining Nava tunnel routes.')
            for mark in options['marks']:
                delete_connections(['-f', 'ipv4' if family == '-4' else 'ipv6', '-D', '--mark', str(mark) + '/0xffffffff'])
            # Old 1.14 native DNS redirects may be unmarked. Match only NAT
            # DNS flows whose reply source is Nava's virtual DNS address.
            for protocol in ('udp', 'tcp'):
                delete_connections(['-f', 'ipv4' if family == '-4' else 'ipv6', '-D', '-p', protocol,
                                    '--dport', '53', '--dst-nat', '--reply-src',
                                    '198.18.0.2' if family == '-4' else 'fdfe:dcba:9876::2'])
    atomic_json(RUN / 'network-stop.json', {})
    atomic_json(RUN / 'network-status.json', {'state': 'off'})


def prepare_start():
    if core_pids():
        return
    cleanup()
    document = read_command(['nft', '-j', 'list', 'ruleset'])
    if any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == 'sing-box' for item in document.get('nftables', [])):
        # Upstream uses one fixed table name. Do not let a new core replace
        # a leftover table whose ownership was not verified as Nava's.
        raise NavaError('A redirect table from another sing-box service remains. Stop or clean that service before starting Nava.')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if sys.argv[1:] == ['begin-stop']:
            begin_stop()
        elif sys.argv[1:] == ['cleanup']:
            cleanup()
        elif sys.argv[1:] == ['prepare-start']:
            prepare_start()
        else:
            raise NavaError('Invalid network lifecycle action.')
    except NavaError as exc:
        from manager import atomic_json
        atomic_json(RUN / 'network-status.json', {'state': 'error', 'message': str(exc)})
        print(str(exc), file=sys.stderr)
        sys.exit(1)
