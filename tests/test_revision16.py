"""Default has no DNS side effects; stopping restores only Nava resources."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
import network_cleanup as net
from subscription import NavaError, build_config, parse_subscription_bundle


def profile():
    return {'dns': {'servers': [
        {'type': 'tcp', 'tag': 'remote', 'server': '8.8.8.8', 'detour': 'Provider group', 'domain_resolver': 'bootstrap-local'},
        {'type': 'local', 'tag': 'direct-local'}, {'type': 'local', 'tag': 'bootstrap-local'}],
        'final': 'bootstrap-local', 'rules': [{'clash_mode': 'Global', 'server': 'remote'},
                                            {'clash_mode': 'Direct', 'server': 'direct-local'}, {'server': 'remote'}]},
        'route': {'default_domain_resolver': 'bootstrap-local'},
        'outbounds': [{'type': 'trojan', 'tag': 'Provider node', 'server': 'proxy.nara.test', 'server_port': 443, 'password': 'test-only'},
                      {'type': 'selector', 'tag': 'Provider group', 'outbounds': ['Provider node'], 'default': 'Provider node'}]}


class DefaultDNSTests(unittest.TestCase):
    def test_reported_json_is_not_rewritten_or_connected_to_a_new_dns_path(self):
        source, original = profile(), profile()
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        config = build_config(nodes, subscription_dns=dns, subscription_context=context)
        self.assertNotIn('dns', config)
        self.assertNotIn('default_domain_resolver', config['route'])
        self.assertTrue(config['inbounds'][0]['auto_route'])
        self.assertTrue(config['inbounds'][0]['auto_redirect'])
        self.assertEqual(config['inbounds'][0]['dns_mode'], 'disabled')
        self.assertFalse(any(item.get('tag') == 'nava-dns-in' for item in config['inbounds']))
        self.assertFalse(any(rule.get('action') == 'hijack-dns' or 'port' in rule for rule in config['route']['rules']))
        self.assertEqual(source, original)
        self.assertEqual(dns, original['dns'])

    def test_apply_default_only_resolves_vpn_endpoint_and_saves_original_json_dns(self):
        source = profile()
        # A provider can legitimately use the name 'bootstrap'. Default must
        # not run Nava's hostname pinning helper on that untouched JSON.
        source['dns']['servers'].append({'type': 'https', 'tag': 'bootstrap', 'server': 'dns.provider.test', 'domain_resolver': 'bootstrap-local'})
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'DATA', Path(directory)), patch.object(m, 'RUN', Path(directory)), patch.object(m, 'running', return_value=False), patch.object(m, 'service') as service, patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'probe', return_value=True), patch.object(m.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('203.0.113.8', 443))]) as lookup:
            m.activate(m.DEFAULTS, {'nodes': nodes, 'dns': dns, 'dns_context': context})
            self.assertNotIn('dns', m.read_json(m.DATA / 'config.json'))
            lookup.assert_called_once()
            self.assertEqual(lookup.call_args.args[0], 'proxy.nara.test')
            runtime = m.read_json(m.DATA / 'config.json')
            self.assertNotIn('default_domain_resolver', runtime['route'])
            self.assertEqual([call.args[0] for call in service.call_args_list], ['stop', 'start', 'disable'])


class NetworkCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        for name, value in [('RUN', self.base / 'run'), ('CONFIG', self.base / 'config.json'), ('PROC', self.base / 'proc'), ('FW4_INCLUDE', self.base / 'include.nft')]:
            handle = patch.object(net, name, value); handle.start(); self.addCleanup(handle.stop)
        net.PROC.mkdir()
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(profile()), include_context=True)
        m.atomic_json(net.CONFIG, build_config(nodes, subscription_dns=dns, subscription_context=context))
        self.document = {'nftables': [
            {'table': {'family': 'inet', 'name': 'sing-box'}},
            {'rule': {'family': 'inet', 'table': 'sing-box', 'chain': 'prerouting', 'handle': 3, 'expr': [{'match': {'right': 'nava0'}}]}},
            {'rule': {'family': 'inet', 'table': 'fw4', 'chain': 'input', 'handle': 42, 'comment': net.COMMENT, 'expr': [{'match': {'right': 'nava0'}}]}},
            {'rule': {'family': 'inet', 'table': 'fw4', 'chain': 'forward', 'handle': 43, 'comment': net.COMMENT, 'expr': [{'match': {'right': 'other0'}}]}},
            {'table': {'family': 'inet', 'name': 'other-proxy'}}]}
        self.rules = [{'priority': 0, 'table': 'local'}, {'priority': 32766, 'table': 'main'},
                      {'priority': 20220, 'fwmark': '0x6e02', 'goto': 20222},
                      {'priority': 20221, 'fwmark': '0x6e01', 'table': 20220},
                      {'priority': 20222, 'action': 'nop'},
                      {'priority': 42020, 'fwmark': '0x6e02', 'not': True, 'table': 20220},
                      {'priority': 20220, 'fwmark': '0x99', 'table': 'main'}]
        self.calls = []
        self.links = [{'ifname': 'nava0'}, {'ifname': 'br-lan'}]
        def execute(args):
            self.calls.append(args)
            if args == ['nft', '-j', 'list', 'ruleset']:
                output = json.dumps(self.document)
            elif args == ['ip', '-j', 'link', 'show']:
                output = json.dumps(self.links)
            elif args[:2] == ['ip', '-j']:
                output = json.dumps(self.rules)
            else:
                output = ''
            return subprocess.CompletedProcess(args, 0, output, '')
        self.execute = execute
        handle = patch.object(net, 'call', side_effect=execute); handle.start(); self.addCleanup(handle.stop)

    def test_removes_only_owned_nft_rules_routes_and_connection_marks(self):
        net.FW4_INCLUDE.write_text('chain input { iifname "nava0" accept comment "' + net.COMMENT + '" }')
        net.begin_stop(); net.cleanup()
        self.assertIn(['nft', 'delete', 'table', 'inet', 'sing-box'], self.calls)
        self.assertIn(['nft', 'delete', 'rule', 'inet', 'fw4', 'input', 'handle', '42'], self.calls)
        self.assertFalse(any('43' in args for args in self.calls))
        self.assertFalse(net.FW4_INCLUDE.exists())
        self.assertFalse(any(args[:3] == ['nft', 'flush', 'ruleset'] or '-F' in args for args in self.calls))
        self.assertFalse(any(args[0] == 'ip' and 'delete' in args and 'main' in args for args in self.calls))
        for family in ('-4', '-6'):
            self.assertIn(['ip', family, 'route', 'flush', 'table', '20220', 'dev', 'nava0'], self.calls)
        ct = [args for args in self.calls if args[0] == 'conntrack']
        self.assertEqual(len(ct), 10)
        self.assertTrue(all('--mark' in args or ('--dst-nat' in args and '--dport' in args and '--reply-src' in args) for args in ct))
        self.assertEqual(m.read_json(net.RUN / 'network-status.json'), {'state': 'off'})

    def test_unrelated_sing_box_table_include_and_firewall_rules_are_preserved(self):
        self.document['nftables'][1]['rule']['expr'] = [{'match': {'right': 'other0'}}]
        self.document['nftables'] = [item for item in self.document['nftables'] if item.get('rule', {}).get('handle') != 42]
        net.FW4_INCLUDE.write_text('iifname "other0" accept comment "' + net.COMMENT + '"')
        net.begin_stop(); net.cleanup()
        self.assertFalse(any('delete' in args or 'flush' in args or '-D' in args for args in self.calls))
        self.assertTrue(net.FW4_INCLUDE.exists())

    def test_start_does_not_allow_core_to_replace_an_unverified_foreign_table(self):
        self.document = {'nftables': [{'table': {'family': 'inet', 'name': 'sing-box'}}]}
        with self.assertRaisesRegex(NavaError, 'another sing-box service remains'):
            net.prepare_start()
        self.assertFalse(any('delete' in args or 'flush' in args for args in self.calls))

    def test_waits_for_core_exit_before_any_network_mutation(self):
        with patch.object(net, 'core_pids', side_effect=[[17], [], []]), patch.object(net.time, 'sleep') as sleep:
            net.cleanup()
        sleep.assert_called_once_with(.2)
        self.assertIn(['nft', 'delete', 'table', 'inet', 'sing-box'], self.calls)

    def test_core_stop_timeout_preserves_all_network_resources(self):
        with patch.object(net, 'core_pids', return_value=[17]), patch.object(net.time, 'monotonic', side_effect=[0, 16]):
            with self.assertRaisesRegex(NavaError, 'still stopping'):
                net.cleanup()
        self.assertEqual(self.calls, [])

    def test_other_core_process_prevents_shared_table_cleanup(self):
        with patch.object(net, 'core_pids', side_effect=[[], [18]]):
            with self.assertRaisesRegex(NavaError, 'Another sing-box'):
                net.cleanup()
        self.assertEqual(self.calls, [])

    def test_saved_ownership_cleans_residual_routes_after_core_removed_nft_table(self):
        net.begin_stop()
        self.document = {'nftables': []}
        net.cleanup()
        self.assertTrue(any(args[0] == 'ip' and 'delete' in args for args in self.calls))
        self.assertTrue(any(args[0] == 'conntrack' for args in self.calls))

    def test_connection_cleanup_failure_is_visible_and_retains_retry_manifest(self):
        net.begin_stop()
        def failure(args):
            if args[0] == 'conntrack':
                return subprocess.CompletedProcess(args, 1, '', 'Permission denied')
            return self.execute(args)
        with patch.object(net, 'call', side_effect=failure):
            with self.assertRaisesRegex(NavaError, 'connection state'):
                net.cleanup()
        self.assertTrue(m.read_json(net.RUN / 'network-stop.json')['owned'])

    def test_zero_matching_connections_is_success(self):
        def empty(args):
            if args[0] == 'conntrack':
                return subprocess.CompletedProcess(args, 1, '', 'conntrack: 0 flow entries have been deleted.')
            return self.execute(args)
        with patch.object(net, 'call', side_effect=empty):
            net.cleanup()
        self.assertEqual(m.read_json(net.RUN / 'network-status.json')['state'], 'off')

    def test_kernel_removed_tun_does_not_fail_on_a_nonexistent_device_filter(self):
        net.begin_stop()
        self.links = [{'ifname': 'br-lan'}]
        net.cleanup()
        self.assertFalse(any(args[0] == 'ip' and 'route' in args and 'flush' in args for args in self.calls))
        self.assertTrue(any(args[0] == 'conntrack' for args in self.calls))
        self.assertEqual(m.read_json(net.RUN / 'network-status.json')['state'], 'off')

    def test_managed_core_pid_detection_does_not_include_checks_or_other_services(self):
        for pid, words in [(17, [net.CORE, 'run', '-c', str(net.CONFIG)]), (18, ['/usr/bin/sing-box', 'run', '-c', '/etc/other.json']), (19, [net.CORE, 'check', '-c', str(net.CONFIG)])]:
            folder = net.PROC / str(pid); folder.mkdir()
            (folder / 'cmdline').write_bytes(b'\0'.join(word.encode() for word in words) + b'\0')
        self.assertEqual(net.core_pids(), [17])
        self.assertEqual(net.core_pids(other=True), [18])

    def test_init_hooks_defer_dns_restore_until_after_core_and_network_stop(self):
        source = (Path(__file__).resolve().parents[1] / 'luci-app-nava/root/etc/init.d/nava').read_text()
        source = source.replace('/usr/bin/python3', 'test_python')
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'lifecycle.sh'
            script.write_text('test_python() { printf "%s\\n" "$*"; }\n' + source + '\nstop_service\nprintf "core exited\\n"\nservice_stopped\n')
            result = subprocess.run(['sh', str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = result.stdout.splitlines()
        self.assertEqual(events, ['/usr/lib/nava/network_cleanup.py begin-stop', 'core exited',
                                  '/usr/lib/nava/network_cleanup.py cleanup', '/usr/lib/nava/dns_forwarding.py reset'])

    def test_cleanup_failure_reaches_the_user_instead_of_generic_command_error(self):
        with patch.object(m, 'RUN', net.RUN), patch.object(m, 'command', return_value=subprocess.CompletedProcess([], 1)):
            m.atomic_json(net.RUN / 'network-status.json', {'state': 'error', 'message': 'Could not clear Nava connection state.'})
            with self.assertRaisesRegex(NavaError, 'Could not clear Nava connection state'):
                m.service('stop')


if __name__ == '__main__':
    unittest.main()
