import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import diagnostics as d
import manager as m
from subscription import NavaError, build_config, parse_subscription


class RevisionTests(unittest.TestCase):
    def test_custom_provider_ip_matches_the_working_preset(self):
        nodes, _ = parse_subscription('trojan://secret@proxy.example:443')
        for mode, ip in [('cloudflare', '1.1.1.1'), ('google', '8.8.8.8'), ('opendns', '208.67.222.222')]:
            preset = build_config(nodes, dns_mode=mode)
            custom = build_config(nodes, dns_mode='custom', custom_dns=ip)
            custom['dns']['final'] = 'remote-dns'
            custom['dns']['servers'][1]['tag'] = 'remote-dns'
            self.assertEqual(custom, preset)

    def test_quad9_adguard_use_https_at_the_entered_ip(self):
        nodes, _ = parse_subscription('trojan://secret@proxy.example:443')
        for ip, name in [('9.9.9.9', 'dns.quad9.net'), ('94.140.14.14', 'dns.adguard-dns.com')]:
            config = build_config(nodes, dns_mode='custom', custom_dns=ip)
            dns = config['dns']
            self.assertEqual(dns['servers'][0], {'type': 'udp', 'tag': 'bootstrap', 'server': ip})
            remote = dns['servers'][1]
            self.assertEqual(remote['type'], 'https')
            self.assertEqual(remote['server'], ip)
            self.assertEqual(remote['tls'], {'enabled': True, 'server_name': name})
            self.assertEqual(remote['detour'], 'proxy')
            self.assertEqual(remote['path'], '/dns-query')
            self.assertNotIn('1.1.1.1', json.dumps(config))
            self.assertNotIn('provider-dns', json.dumps(config))

    def test_other_ip_uses_tcp_but_explicit_udp_is_preserved(self):
        nodes, _ = parse_subscription('trojan://secret@proxy.example:443')
        for value, expected in [('203.0.113.53', 'tcp'), ('udp://9.9.9.9:9953', 'udp'), ('tcp://9.9.9.9:5353', 'tcp')]:
            remote = build_config(nodes, dns_mode='custom', custom_dns=value)['dns']['servers'][-1]
            self.assertEqual(remote['type'], expected)

    def test_policy_routed_pppoe_wan_from_netifd(self):
        response = {'interface': [{'interface': 'wan', 'up': True, 'l3_device': 'pppoe-wan',
                                   'route': [{'target': '0.0.0.0', 'mask': 0, 'table': 100, 'metric': 10}]},
                                  {'interface': 'nava', 'up': True, 'l3_device': 'nava0', 'route': [{'target': '0.0.0.0', 'mask': 0}]}]}
        with patch.object(m, 'command', return_value=type('Result', (), {'returncode': 0, 'stdout': json.dumps(response)})()):
            self.assertEqual(d.wan_interface(), 'pppoe-wan')

    def test_custom_route_table_when_main_has_no_default(self):
        def query(args, **_):
            payload = {} if args[0] == 'ubus' else [{'dst': 'default', 'dev': 'nava0'}, {'dst': 'default', 'dev': 'eth2', 'table': 100}]
            return type('Result', (), {'returncode': 0, 'stdout': json.dumps(payload)})()
        with patch.object(m, 'command', side_effect=query):
            self.assertEqual(d.wan_interface(), 'eth2')

    def test_route_fallback_without_ip_json(self):
        def query(args, **_):
            if args[0] == 'ubus':
                return type('Result', (), {'returncode': 0, 'stdout': '{}'})()
            if '-j' in args:
                return type('Result', (), {'returncode': 1, 'stdout': ''})()
            return type('Result', (), {'returncode': 0, 'stdout': 'default via 192.0.2.1 dev eth0 table 123 metric 10\n'})()
        with patch.object(m, 'command', side_effect=query):
            self.assertEqual(d.wan_interface(), 'eth0')

    def test_add_downloads_before_save_and_preserves_active_connection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'DATA', Path(directory)), patch.object(m, 'service') as service:
            old_url = 'https://old.example/sub'
            old_id = m._subscription_id(old_url)
            saved = {**m.DEFAULTS, 'subscriptions': [{'id': old_id, 'name': 'Active', 'url': old_url}], 'active_subscription': old_id, 'subscription_url': old_url}
            m.atomic_json(m.DATA / 'settings.json', saved)
            new_url = 'http://new.example/sub'
            config = m.validate_settings({'action': 'add_subscription', 'subscription_url': new_url, 'subscription_name': 'New'})
            sid = config['operation_subscription']
            nodes, _ = parse_subscription('trojan://secret@proxy.example:443#Loaded')
            cache = {'nodes': nodes, 'updated': 123, 'source_hash': hashlib.sha256(new_url.encode()).hexdigest()}
            with patch.object(m, 'fetch_subscription', return_value=cache) as fetch:
                m.execute('add_subscription', config)
            self.assertEqual(fetch.call_args.args[0]['subscription_url'], new_url)
            self.assertEqual(m.settings()['active_subscription'], old_id)
            self.assertEqual(m.read_json(m.DATA / 'subscription.json')['entries'][sid]['nodes'][0]['name'], 'Loaded')
            before = (m.DATA / 'settings.json').read_bytes()
            failed = m.validate_settings({'action': 'add_subscription', 'subscription_url': 'https://broken.example/sub', 'subscription_name': 'Broken'})
            with patch.object(m, 'fetch_subscription', side_effect=NavaError('Invalid subscription')):
                with self.assertRaises(NavaError):
                    m.execute('add_subscription', failed)
            self.assertEqual((m.DATA / 'settings.json').read_bytes(), before)
            service.assert_not_called()


if __name__ == '__main__':
    unittest.main()
