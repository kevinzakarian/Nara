"""Country routing: no offline network effects, transactional lists and real core decisions."""
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
import routing as r
from subscription import NavaError, parse_subscription


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        handle = patch.object(m, 'DATA', self.data); handle.start(); self.addCleanup(handle.stop)
        self.nodes, _ = parse_subscription('trojan://secret@203.0.113.8:443')

    def test_offline_apply_changes_only_saved_routing_including_without_lists(self):
        saved = {**m.DEFAULTS, 'dns_mode': 'custom', 'custom_dns': '94.140.14.14', 'autostart': True}
        m.atomic_json(self.data / 'settings.json', saved)
        for name in ('config.json', 'subscription.json', 'core.json', 'routing-state.json'):
            (self.data / name).write_text('{"untouched":true}')
        before = {path.name: path.read_bytes() for path in self.data.iterdir() if path.name != 'settings.json'}
        config = m.validate_settings({'action': 'save_routing', 'routing_enabled': True, 'ip_source': 'ir', 'domain_source': 'cn',
                                      'dns_mode': 'google', 'selected': 'unsaved', 'autostart': False,
                                      'direct_ips': '198.51.100.8', 'direct_domains': 'direct.test', 'vpn_ips': '203.0.113.0/24', 'vpn_domains': 'vpn.test'})
        with patch.object(m, 'running', return_value=False), patch.object(m, 'command') as command, patch.object(m, 'service') as service, patch.object(m, 'activate') as activate, patch.object(m, 'download') as download, patch.object(m, 'apply_autostart') as autostart:
            self.assertIn('when you connect', m.execute('save_routing', config))
            for tool in (command, service, activate, download, autostart): tool.assert_not_called()
        stored = m.read_json(self.data / 'settings.json')
        self.assertEqual(stored, {**saved, 'routing': r.normalize({'enabled': True, 'ip_source': 'ir', 'domain_source': 'cn', 'direct_ips': '198.51.100.8', 'direct_domains': 'direct.test', 'vpn_ips': '203.0.113.0/24', 'vpn_domains': 'vpn.test'})})
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.data.iterdir() if path.name != 'settings.json'})

    def test_online_missing_lists_fails_before_stopping_previous_connection(self):
        config = {**m.DEFAULTS, 'routing': {'enabled': True, 'ip_source': 'ir', 'domain_source': 'ru'}}
        with patch.object(m, 'running', return_value=True), patch.object(m, 'service') as service:
            with self.assertRaisesRegex(NavaError, 'Routing lists'):
                m.activate(config, {'nodes': self.nodes})
            service.assert_not_called()

    def test_download_failure_discards_partial_generation_preserves_manifest_and_runtime(self):
        old = {'files': {}, 'updated': 123}; m.atomic_json(self.data / 'routing-state.json', old)
        def download(url, path, **kwargs):
            if 'geosite-ir' in url: raise NavaError('test failure')
            path.write_bytes(b'first staged list')
        with self.assertRaisesRegex(NavaError, 'test failure'):
            r.stage(self.data, Path('/unused'), download, m.command, m.check_config, lambda *args: None)
        self.assertEqual(m.read_json(self.data / 'routing-state.json'), old)
        self.assertEqual(list((self.data / 'routing-lists').iterdir()), [])

    def test_prune_preserves_generation_used_by_active_config(self):
        base = self.data / 'routing-lists'; base.mkdir()
        for name in ('old', 'new', 'abandoned'): (base / ('generation-' + name)).mkdir()
        m.atomic_json(self.data / 'config.json', {'route': {'rule_set': [{'path': str(base/'generation-old/ir-ip.srs')}]}})
        r.prune(self.data, {'files': {'ir-ip': {'path': str(base/'generation-new/ir-ip.srs')}}})
        self.assertEqual({p.name for p in base.iterdir()}, {'generation-new', 'generation-old'})

    def test_domain_conversion_does_not_turn_exact_hosts_into_suffixes(self):
        result = r.domain_list('full:exact.test\ndomain:suffix.test\nplain.test\nregexp:^x[0-9]+\\.test$\nkeyword:example\n')
        rule = result['rules'][0]
        self.assertEqual(rule['domain'], ['exact.test'])
        self.assertEqual(rule['domain_suffix'], ['plain.test', 'suffix.test'])
        with self.assertRaises(NavaError): r.domain_list('unsupported:example.test')

    def test_lists_cannot_reference_unmanaged_paths(self):
        path = self.data/'ir-ip.srs'; path.write_bytes(b'test')
        with self.assertRaises(NavaError): r.owned_path(self.data, 'ir-ip', {'path': str(path), 'bytes': 4})

    def test_dns_unchanged_for_all_providers_and_country_combinations(self):
        # The lists only add route decisions; resolver sections and inbound DNS
        # behavior must stay byte-for-byte equivalent to routing disabled.
        generation = self.data/'routing-lists/generation-test'; generation.mkdir(parents=True)
        files = {}
        for country in r.SOURCES:
            for kind in ('ip', 'domain'):
                key = country+'-'+kind; path = generation/(key+'.srs'); path.write_bytes(b'fixture')
                files[key] = {'path': str(path), 'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest()}
        m.atomic_json(self.data/'routing-state.json', {'files': files})
        for mode in ('default', 'cloudflare', 'google', 'opendns', 'custom'):
            for ip in r.SOURCES:
                for domain in r.SOURCES:
                    options = {**m.DEFAULTS, 'dns_mode': mode, 'custom_dns': '94.140.14.14'}
                    with patch.object(m, 'prepare_dns_bootstrap', side_effect=lambda config: config):
                        plain = m.connection_config(options, {'nodes': self.nodes})
                        routed = m.connection_config({**options, 'routing': {'enabled': True, 'ip_source': ip, 'domain_source': domain}}, {'nodes': self.nodes})
                    self.assertEqual(plain.get('dns'), routed.get('dns'))
                    self.assertEqual(plain['inbounds'], routed['inbounds'])
                    if mode == 'default':
                        self.assertNotIn('dns', routed)
                        self.assertNotIn('default_domain_resolver', routed['route'])
                        self.assertFalse(any(rule.get('action') == 'hijack-dns' for rule in routed['route']['rules']))
                    self.assertEqual(routed['route']['final'], 'proxy')
                    self.assertEqual([x['rules'][0]['rule_set'] for x in routed['route']['rules'] if x.get('type') == 'logical'], [['nava-'+domain+'-domain'], ['nava-'+ip+'-ip']])

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Official core not provided')
    def test_actual_core_routes_domain_or_ip_direct_and_nonmatch_via_proxy(self):
        core = os.environ['SING_BOX_TEST_BINARY']
        class Website(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'DIRECT')
            def log_message(self, *args): pass
        class Proxy(Website):
            def do_CONNECT(self):
                self.send_response(200); self.end_headers()
                self.rfile.readline()
                while self.rfile.readline().strip(): pass
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPROXY')
        website = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Website)
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        for server in (website, proxy):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        generation = self.data/'routing-lists/generation-test'; generation.mkdir(parents=True)
        files = {}
        for key, rule in [('ir-ip', {'ip_cidr': ['192.0.2.0/24']}), ('cn-domain', {'domain_suffix': ['matched.test']})]:
            source = generation/(key+'.json'); source.write_text(json.dumps({'version': 3, 'rules': [rule]}))
            path = generation/(key+'.srs')
            subprocess.run([core, 'rule-set', 'compile', str(source), '--output', str(path)], check=True, capture_output=True)
            files[key] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        m.atomic_json(self.data/'routing-state.json', {'files': files})
        options = {**m.DEFAULTS, 'routing': {'enabled': True, 'ip_source': 'ir', 'domain_source': 'cn'}}
        config = m.connection_config(options, {'nodes': self.nodes})
        # Use an unprivileged mixed inbound carrying IP destinations + HTTP
        # sniff metadata instead of installing a TUN on the developer machine.
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
        config['inbounds'] = [{'type': 'mixed', 'tag': 'tun-in', 'listen': '127.0.0.1', 'listen_port': port}]
        config['outbounds'] = [{'type': 'http', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': proxy.server_port}, {'type': 'direct', 'tag': 'direct'}]
        # Allow loopback destinations to reach country rules in this fixture.
        config['route']['rules'] = [rule for rule in config['route']['rules'] if not rule.get('ip_is_private')]
        config['route'].pop('auto_detect_interface', None)
        path = self.data/'test.json'; m.atomic_json(path, config)
        process = subprocess.Popen([core, '--disable-color', 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def stop():
            process.terminate(); process.communicate(timeout=10)
        self.addCleanup(stop)
        for _ in range(100):
            if process.poll() is not None: self.fail(process.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError: time.sleep(.03)
        def request(ip, host, target_port=None):
            with socket.create_connection(('127.0.0.1', port), timeout=3) as stream:
                stream.sendall(b'\x05\x01\x00'); self.assertEqual(stream.recv(2), b'\x05\x00')
                stream.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(ip)+struct.pack('!H', target_port or website.server_port))
                self.assertEqual(stream.recv(10)[1], 0)
                stream.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
                response = b''
                while True:
                    chunk = stream.recv(4096)
                    if not chunk: break
                    response += chunk
                return response
        self.assertTrue(request('127.0.0.1', 'child.matched.test').endswith(b'DIRECT'))
        for dns_port in (53, 853):
            self.assertTrue(request('127.0.0.1', 'child.matched.test', dns_port).endswith(b'PROXY'))
        self.assertTrue(request('127.0.0.1', 'unmatched.test').endswith(b'PROXY'))
        stop()
        source = generation/'ir-ip.json'
        source.write_text(json.dumps({'version': 3, 'rules': [{'ip_cidr': ['127.0.0.1/32']}]}))
        subprocess.run([core, 'rule-set', 'compile', str(source), '--output', str(generation/'ir-ip.srs')], check=True, capture_output=True)
        process = subprocess.Popen([core, '--disable-color', 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if process.poll() is not None: self.fail(process.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError: time.sleep(.03)
        self.assertTrue(request('127.0.0.1', 'unmatched.test').endswith(b'DIRECT'))
        for dns_port in (53, 853):
            self.assertTrue(request('127.0.0.1', 'unmatched.test', dns_port).endswith(b'PROXY'))
        ip_path = generation/'ir-ip.srs'
        files['ir-ip'].update(bytes=ip_path.stat().st_size, sha256=hashlib.sha256(ip_path.read_bytes()).hexdigest())
        m.atomic_json(self.data/'routing-state.json', {'files': files})
        def custom_runtime(custom, country=False):
            nonlocal process
            stop()
            route_options = {'enabled': country, 'ip_source': 'ir', 'domain_source': 'cn', **custom}
            generated = m.connection_config({**m.DEFAULTS, 'routing': route_options}, {'nodes': self.nodes})
            config['route'] = generated['route']
            config['route']['rules'] = [rule for rule in config['route']['rules'] if not rule.get('ip_is_private')]
            config['route'].pop('auto_detect_interface', None)
            m.atomic_json(path, config)
            process = subprocess.Popen([core, '--disable-color', 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(100):
                if process.poll() is not None: self.fail(process.stderr.read().decode())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                except OSError: time.sleep(.03)
        custom_runtime({'direct_domains': 'direct.test\nconflict.test', 'vpn_domains': 'force.direct.test\nconflict.test'})
        self.assertTrue(request('127.0.0.1', 'child.direct.test').endswith(b'DIRECT'))
        self.assertTrue(request('127.0.0.1', 'force.direct.test').endswith(b'PROXY'))
        self.assertTrue(request('127.0.0.1', 'conflict.test').endswith(b'PROXY'))
        self.assertTrue(request('127.0.0.1', 'unmatched.test').endswith(b'PROXY'))
        custom_runtime({'direct_domains': 'direct.test', 'vpn_ips': '127.0.0.2', 'vpn_domains': 'vpn.matched.test'}, country=True)
        self.assertTrue(request('127.0.0.1', 'vpn.matched.test').endswith(b'PROXY'))
        self.assertTrue(request('127.0.0.2', 'direct.test').endswith(b'PROXY'))
        custom_runtime({'direct_ips': '127.0.0.1', 'vpn_domains': 'force.test'})
        self.assertTrue(request('127.0.0.1', 'unmatched.test').endswith(b'DIRECT'))
        self.assertTrue(request('127.0.0.1', 'force.test').endswith(b'PROXY'))
        custom_runtime({'direct_ips': '127.0.0.1', 'vpn_ips': '127.0.0.1'})
        self.assertTrue(request('127.0.0.1', 'unmatched.test').endswith(b'PROXY'))
