import base64
import json
import os
from pathlib import Path
import subprocess
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
from subscription import NavaError, build_config, parse_subscription, parse_subscription_bundle

UUID = '12345678-1234-4234-9234-123456789abc'


def b64(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')


LINKS = [
    'vless://' + UUID + '@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws#London',
    'vmess://' + b64(json.dumps({'v': '2', 'ps': 'Paris', 'add': 'example.com', 'port': '443', 'id': UUID, 'aid': '0', 'net': 'ws', 'path': '/ws', 'tls': 'tls'})),
    'trojan://secret%3Akey@example.com:443?sni=example.com#Berlin',
    'ss://' + b64('aes-128-gcm:secret') + '@example.com:8388#Tokyo',
    'hy2://secret@example.com:443?obfs=salamander&obfs-password=test#Helsinki',
    'tuic://' + UUID + ':secret@example.com:443?alpn=h3#Oslo',
    'anytls://secret@example.com:443#Stockholm',
    'vless://' + UUID + '@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&flow=xtls-rprx-vision#Reality'
]


class SubscriptionTests(unittest.TestCase):
    def test_all_supported_uri_protocols(self):
        nodes, warnings = parse_subscription('\n'.join(LINKS))
        self.assertEqual(len(nodes), 8)
        self.assertEqual(warnings, [])
        self.assertEqual(nodes[0]['outbound']['transport']['headers']['Host'], 'cdn.example.com')
        self.assertEqual(nodes[2]['outbound']['password'], 'secret:key')

    def test_base64_and_plain_are_equivalent(self):
        content = '\n'.join(LINKS)
        self.assertEqual(parse_subscription(content), parse_subscription(b64(content)))

    def test_ipv6_address(self):
        nodes, _ = parse_subscription('trojan://secret@[2001:db8::1]:8443#IPv6')
        self.assertEqual(nodes[0]['outbound']['server'], '2001:db8::1')
        self.assertEqual(nodes[0]['outbound']['server_port'], 8443)

    def test_legacy_shadowsocks(self):
        nodes, _ = parse_subscription('ss://' + b64('aes-256-gcm:pass@example.com:8388') + '#Legacy')
        self.assertEqual(nodes[0]['outbound']['password'], 'pass')

    def test_password_with_colon(self):
        nodes, _ = parse_subscription('ss://' + b64('aes-128-gcm:a:b:c') + '@example.com:8388')
        self.assertEqual(nodes[0]['outbound']['password'], 'a:b:c')

    def test_websocket_early_data(self):
        nodes, _ = parse_subscription('vless://' + UUID + '@example.com:443?type=ws&path=%2Fws%3Fed%3D2048')
        self.assertEqual(nodes[0]['outbound']['transport']['max_early_data'], 2048)
        self.assertEqual(nodes[0]['outbound']['transport']['path'], '/ws')

    def test_native_json_with_groups(self):
        nodes, _ = parse_subscription(LINKS[0])
        native = nodes[0]['outbound'].copy()
        native['tag'] = 'Europe'
        result, warnings = parse_subscription(json.dumps({'outbounds': [native, {'type': 'direct', 'tag': 'direct'}, {'type': 'selector', 'tag': 'proxy', 'outbounds': ['Europe']}], 'inbounds': [{'type': 'mixed', 'listen': '0.0.0.0'}]}))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'Europe')
        self.assertEqual(warnings, [])
        self.assertEqual(build_config(result)['inbounds'][1]['listen'], '127.0.0.1')

    def test_stable_ids_and_deduplication(self):
        nodes, _ = parse_subscription(LINKS[0] + '\n' + LINKS[0].replace('#London', '#Renamed'))
        self.assertEqual(len(nodes), 1)
        renamed, _ = parse_subscription(LINKS[0].replace('#London', '#New'))
        self.assertEqual(nodes[0]['id'], renamed[0]['id'])

    def test_partial_subscription_warns_without_credentials(self):
        _, warnings = parse_subscription(LINKS[0] + '\nvless://SUPERSECRET@example.com:443')
        self.assertEqual(len(warnings), 1)
        self.assertNotIn('SUPERSECRET', warnings[0])

    def test_malformed_inputs(self):
        for content in ['', '<html>login required</html>', 'invalid', '{}', '[]', '{broken', 'proxies:\n  - name: foo', 'trojan://abc@example.com:99999', 'vless://secret@/path', b'\xff']:
            with self.subTest(content=content), self.assertRaises(NavaError):
                parse_subscription(content)

    def test_limits(self):
        for content in ['a' * (8 * 1024 * 1024 + 1), '\n'.join([LINKS[0]] * 1001)]:
            with self.assertRaises(NavaError):
                parse_subscription(content)

    def test_unsupported_transports_fail_explicitly(self):
        for transport in ['xhttp', 'kcp', 'quic']:
            with self.subTest(transport=transport), self.assertRaisesRegex(NavaError, 'Unsupported transport'):
                parse_subscription('vless://' + UUID + '@example.com:443?type=' + transport)

    def test_external_executables_and_paths_rejected(self):
        for patch in [{'plugin': '/bin/sh'}, {'tls': {'enabled': True, 'certificate_path': '/etc/shadow'}}, {'detour': 'direct'}, {'tls': {'ech': {'config_path': '/etc/passwd'}}}]:
            outbound = {'type': 'shadowsocks', 'server': 'example.com', 'server_port': 8388, 'method': 'aes-128-gcm', 'password': 'secret', **patch}
            with self.subTest(patch=patch), self.assertRaises(NavaError):
                parse_subscription(json.dumps({'outbounds': [outbound]}))

    def test_malformed_native_types_do_not_poison_status_cache(self):
        for patch in [{'type': []}, {'tls': 'invalid'}, {'tls': []}, {'multiplex': 42}, {'obfs': True}]:
            outbound = {'type': 'trojan', 'server': 'example.com', 'server_port': 443, 'password': 'secret', **patch}
            with self.subTest(patch=patch), self.assertRaises(NavaError):
                parse_subscription(json.dumps({'outbounds': [outbound]}))

    def test_shadowsocks_plugin_rejected(self):
        for link in [LINKS[3].split('#')[0], 'ss://' + b64('aes-128-gcm:pass@example.com:8388')]:
            with self.assertRaisesRegex(NavaError, 'plugins'):
                parse_subscription(link + '?plugin=obfs-local')

    def test_tls_is_verified_by_default(self):
        nodes, _ = parse_subscription('\n'.join(LINKS))
        self.assertFalse(any(n['outbound'].get('tls', {}).get('insecure', False) for n in nodes))

    def test_explicit_insecure_setting_preserved(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443?allowInsecure=1')
        self.assertTrue(nodes[0]['outbound']['tls']['insecure'])

    def test_private_routing_dns_and_ipv6(self):
        nodes, _ = parse_subscription(LINKS[0])
        config = build_config(nodes, ipv6=False, dns_mode="google")
        self.assertEqual(config['route']['rules'][0], {'port': 53, 'action': 'hijack-dns'})
        self.assertIn({'ip_version': 6, 'action': 'reject'}, config['route']['rules'])
        self.assertEqual(len(config['inbounds'][0]['address']), 2)  # IPv6 captured, not leaked.
        self.assertTrue(config['inbounds'][0]['auto_redirect'])
        self.assertEqual(config['dns']['servers'][1]['detour'], 'proxy')

    def test_json_subscription_dns_is_ignored_in_default(self):
        native = {'type': 'trojan', 'tag': 'Node', 'server': 'example.com', 'server_port': 443, 'password': 'secret',
                  'tls': {'enabled': True, 'server_name': 'example.com'}}
        content = json.dumps({'dns': {'servers': [{'type': 'https', 'tag': 'provider-dns', 'server': '9.9.9.9',
                  'path': '/dns-query', 'tls': {'enabled': True, 'server_name': 'dns.quad9.net'}, 'detour': 'provider-proxy'}],
                  'final': 'provider-dns'}, 'outbounds': [native]})
        nodes, warnings, subscription_dns = parse_subscription_bundle(content)
        self.assertEqual(warnings, [])
        config = build_config(nodes, dns_mode='default', subscription_dns=subscription_dns)
        self.assertNotIn('dns', config)
        self.assertNotIn('default_domain_resolver', config['route'])
        self.assertNotIn({'port': 53, 'action': 'hijack-dns'}, config['route']['rules'])

    def test_dns_presets_and_custom(self):
        nodes, _ = parse_subscription(LINKS[0])
        self.assertEqual(build_config(nodes, dns_mode='google')['dns']['servers'][1]['server'], '8.8.8.8')
        self.assertEqual(build_config(nodes, dns_mode='opendns')['dns']['servers'][1]['server'], '208.67.222.222')
        custom = build_config(nodes, dns_mode='custom', custom_dns='9.9.9.9, dns.quad9.net')
        self.assertEqual(custom['dns']['final'], 'custom-dns-1')
        self.assertEqual(custom['dns']['servers'][0]['tag'], 'bootstrap')
        self.assertEqual(custom['dns']['servers'][0]['server'], '9.9.9.9')
        self.assertNotIn('1.1.1.1', json.dumps(custom))
        with self.assertRaises(NavaError):
            build_config(nodes, dns_mode='custom', custom_dns='not a dns')

    def test_default_does_not_add_dns_or_force_a_resolver(self):
        nodes, _ = parse_subscription(LINKS[0])
        config = build_config(nodes)
        self.assertNotIn('dns', config)
        self.assertNotIn('default_domain_resolver', config['route'])
        self.assertNotIn({'port': 53, 'action': 'hijack-dns'}, config['route']['rules'])
        self.assertNotIn('1.1.1.1', json.dumps(config))

    def dns_subscription(self):
        return {'dns': {'servers': [
                    {'type': 'udp', 'tag': 'provider-local', 'server': '9.9.9.9'},
                    {'type': 'https', 'tag': 'provider-dns', 'server': 'dns.quad9.net', 'domain_resolver': 'provider-local',
                     'detour': 'Provider group'}],
                'rules': [{'domain_suffix': ['example.org'], 'action': 'route', 'server': 'provider-local'}],
                'final': 'provider-dns', 'strategy': 'prefer_ipv6', 'disable_cache': True},
                'route': {'default_domain_resolver': 'provider-local'},
                'outbounds': [{'type': 'trojan', 'tag': 'Provider node', 'server': 'example.com', 'server_port': 443, 'password': 'secret'},
                              {'type': 'selector', 'tag': 'Provider group', 'outbounds': ['Provider node'], 'default': 'Provider node'}]}

    def test_default_ignores_dns_rules_strategy_and_dependencies(self):
        source = self.dns_subscription()
        nodes, warnings, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        config = build_config(nodes, ipv6=False, subscription_dns=dns, subscription_context=context)
        self.assertEqual(warnings, [])
        self.assertNotIn('dns', config)
        self.assertNotIn('default_domain_resolver', config['route'])
        self.assertNotIn({'port': 53, 'action': 'hijack-dns'}, config['route']['rules'])
        self.assertFalse({'Provider group', 'Provider node'} & {o['tag'] for o in config['outbounds']})
        self.assertEqual(dns, source['dns'])

    def test_custom_replaces_subscription_dns_without_hidden_cloudflare(self):
        source = self.dns_subscription()
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        for custom in ['9.9.9.9', '8.8.8.8, 208.67.222.222', '2001:4860:4860::8888',
                       'tcp://9.9.9.9:5353', 'https://dns.quad9.net/dns-query', 'tls://dns.quad9.net:853']:
            with self.subTest(custom=custom):
                config = build_config(nodes, dns_mode='custom', custom_dns=custom, subscription_dns=dns, subscription_context=context)
                self.assertEqual(config['dns']['final'], 'custom-dns-1')
                self.assertNotIn('provider-dns', json.dumps(config))
                self.assertNotIn('1.1.1.1', json.dumps(config))
                self.assertNotIn('cloudflare', json.dumps(config))
                self.assertIn({'port': 53, 'action': 'hijack-dns'}, config['route']['rules'])
        doh = build_config(nodes, dns_mode='custom', custom_dns='https://dns.quad9.net/dns-query')['dns']
        self.assertEqual(next(s for s in doh['servers'] if s['tag'] == 'custom-dns-1')['type'], 'https')
        self.assertEqual(next(s for s in doh['servers'] if s['tag'] == 'custom-dns-1')['server'], 'dns.quad9.net')

    def test_invalid_custom_dns_does_not_fall_back_to_cloudflare(self):
        nodes, _ = parse_subscription(LINKS[0])
        for value in ['', 'not a dns', 'file:///etc/resolv.conf', 'https://user:password@dns.example/query', 'udp://9.9.9.9:99999']:
            with self.subTest(value=value), self.assertRaises(NavaError):
                build_config(nodes, dns_mode='custom', custom_dns=value)

    def test_subscription_dns_does_not_import_external_files(self):
        source = self.dns_subscription()
        source['dns']['servers'] = [{'type': 'hosts', 'path': '/etc/shadow'}]
        with self.assertRaisesRegex(NavaError, 'external files'):
            parse_subscription_bundle(json.dumps(source))

    def test_default_ignores_unresolved_dns_dependency(self):
        source = self.dns_subscription()
        source['dns']['servers'][1]['detour'] = 'Missing group'
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        self.assertNotIn('dns', build_config(nodes, subscription_dns=dns, subscription_context=context))
        self.assertEqual(build_config(nodes, dns_mode='google', subscription_dns=dns, subscription_context=context)['dns']['final'], 'remote-dns')

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY for core DNS validation')
    def test_dns_modes_with_official_core(self):
        source = self.dns_subscription()
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        scenarios = [('default', '', dns, context), ('default', '', None, None), ('cloudflare', '', dns, context),
                     ('google', '', dns, context), ('opendns', '', dns, context), ('custom', '9.9.9.9', dns, context), ('custom', '94.140.14.14', dns, context), ('custom', '203.0.113.53', dns, context),
                     ('custom', '9.9.9.9, 8.8.8.8', dns, context), ('custom', 'https://dns.quad9.net/dns-query', dns, context),
                     ('custom', 'tls://dns.quad9.net:853', dns, context), ('custom', '2001:4860:4860::8888', dns, context)]
        for mode, custom, subscription_dns, subscription_context in scenarios:
            with self.subTest(mode=mode, custom=custom), tempfile.TemporaryDirectory() as directory:
                config = build_config(nodes, dns_mode=mode, custom_dns=custom, subscription_dns=subscription_dns, subscription_context=subscription_context)
                if sys.platform == 'darwin':
                    config['inbounds'][0].update(auto_redirect=False, interface_name='utun99')
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(config))
                result = subprocess.run([os.environ['SING_BOX_TEST_BINARY'], 'check', '-c', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY for local DNS round-trip testing')
    def test_custom_dns_changes_real_queries_with_official_core(self):
        nodes, _ = parse_subscription(LINKS[0])
        question = b'\x04nava\x04test\x00' + struct.pack('!HH', 1, 1)
        query = struct.pack('!6H', 123, 0x0100, 1, 0, 0, 0) + question
        # The original destination is unused loopback. A successful reply must
        # come from the selected custom DNS through the generated hijack rule.
        for answer_ip in ['192.0.2.123', '192.0.2.124']:
            with self.subTest(answer=answer_ip), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, tempfile.TemporaryDirectory() as directory:
                resolver.bind(('127.0.0.1', 0))
                resolver.settimeout(0.2)
                client.bind(('127.0.0.1', 0))
                client.settimeout(0.2)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                    reservation.bind(('127.0.0.1', 0))
                    inbound_port = reservation.getsockname()[1]
                requests, stop = [], threading.Event()
                def respond():
                    while not stop.is_set():
                        try:
                            packet, address = resolver.recvfrom(4096)
                        except socket.timeout:
                            continue
                        requests.append(packet)
                        answer = packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + packet[12:]
                        answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(answer_ip)
                        resolver.sendto(answer, address)
                thread = threading.Thread(target=respond, daemon=True)
                thread.start()
                config = build_config(nodes, dns_mode='custom', custom_dns='udp://127.0.0.1:%d' % resolver.getsockname()[1])
                config['inbounds'] = [item for item in config['inbounds'] if item['tag'] == 'nava-dns-in']
                config['inbounds'][0]['listen_port'] = inbound_port
                config['outbounds'] = [{'type': 'selector', 'tag': 'proxy', 'outbounds': ['direct']}, {'type': 'direct', 'tag': 'direct'}]
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(config))
                process = subprocess.Popen([os.environ['SING_BOX_TEST_BINARY'], 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    response, deadline = None, time.monotonic() + 5
                    while response is None and time.monotonic() < deadline and process.poll() is None:
                        client.sendto(query, ('127.0.0.1', inbound_port))
                        try:
                            response, _ = client.recvfrom(4096)
                        except socket.timeout:
                            pass
                    diagnostics = process.stderr.read().decode() if process.poll() is not None else 'Core did not return the custom DNS response.'
                    self.assertIsNotNone(response, diagnostics)
                    self.assertEqual(response[-4:], socket.inet_aton(answer_ip))
                    self.assertTrue(requests, 'Configured custom DNS was not queried.')
                finally:
                    process.terminate()
                    process.communicate(timeout=5)
                    stop.set()
                    thread.join(timeout=1)

    def test_manual_selection_and_missing_node(self):
        nodes, _ = parse_subscription(LINKS[0])
        self.assertEqual(build_config(nodes, nodes[0]['id'])['outbounds'][0]['default'], nodes[0]['id'])
        with self.assertRaises(NavaError):
            build_config(nodes, 'missing')

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY to run real core validation')
    def test_configs_with_official_core(self):
        for index, link in enumerate(LINKS):
            nodes, _ = parse_subscription(link)
            for ipv6 in [True, False]:
                with self.subTest(protocol=index, ipv6=ipv6), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'config.json'
                    config = build_config(nodes, ipv6=ipv6)
                    if sys.platform == 'darwin':
                        # Linux-only routing cannot initialize in a macOS binary.
                        # Keep all protocol/DNS/rule checks; Linux runs the exact config.
                        config['inbounds'][0]['auto_redirect'] = False
                        config['inbounds'][0]['interface_name'] = 'utun99'
                    path.write_text(json.dumps(config))
                    result = subprocess.run([os.environ['SING_BOX_TEST_BINARY'], 'check', '-c', str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
