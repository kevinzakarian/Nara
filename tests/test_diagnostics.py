import json
import http.server
import os
from pathlib import Path
import subprocess
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import diagnostics as d
import manager as m
from subscription import NavaError, parse_subscription


class DiagnosticTests(unittest.TestCase):
    def test_aggregate_best_is_from_successful_server(self):
        results = [{'name': 'Blocked', 'url_test': {'state': 'restricted', 'ms': 20, 'http_code': 403}},
                   {'name': 'Fast', 'url_test': {'state': 'ok', 'ms': 70, 'http_code': 204}},
                   {'name': 'Slow', 'url_test': {'state': 'ok', 'ms': 120, 'http_code': 204}}]
        value = d.aggregate(results, 'url_test')
        self.assertEqual(value['server'], 'Fast')
        self.assertEqual(value['ms'], 70)
        self.assertEqual(value['passed'], 2)
        self.assertEqual(value['tested'], 3)
        self.assertEqual(d.aggregate(results[:1], 'url_test')['state'], 'restricted')

    def test_udp_protocols_do_not_report_false_tcp_failure(self):
        self.assertEqual(d.tcping(None, 'wan', 'hysteria2')['state'], 'not_applicable')
        result = d.aggregate([{'tcping': {'state': 'not_applicable'}}], 'tcping')
        self.assertEqual(result['state'], 'not_applicable')

    def test_test_target_is_whitelisted_and_cannot_change_active_subscription(self):
        saved = {**m.DEFAULTS, 'active_subscription': 'sub-1234567890abcdef', 'dns_mode': 'custom', 'custom_dns': '9.9.9.9'}
        with patch.object(m, 'settings', return_value=saved):
            result = m.validate_settings({'action': 'test_subscriptions', 'test_target': 'microsoft', 'dns_mode': 'default', 'subscription_id': 'wrong'})
            self.assertEqual(result['active_subscription'], saved['active_subscription'])
            self.assertEqual(result['custom_dns'], '9.9.9.9')
            with self.assertRaises(NavaError):
                m.validate_settings({'action': 'test_subscriptions', 'test_target': 'https://anything.test'})

    def test_editor_full_link_requires_write_permission(self):
        acl = json.loads((Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/share/rpcd/acl.d/luci-app-nava.json').read_text())['luci-app-nava']
        self.assertNotIn('subscription', acl['read']['ubus']['nava'])
        self.assertIn('subscription', acl['write']['ubus']['nava'])
        with patch.object(m, 'settings', return_value={'subscriptions': [{'id': 'a', 'url': 'http://example.test/private-token', 'name': 'Home'}]}):
            result = m.subscription_details({'subscription_id': 'a'})
        self.assertEqual(result['url'], 'http://example.test/private-token')

    def test_all_tests_preserve_settings_and_connection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'DATA', Path(directory)), patch.object(m, 'RUN', Path(directory)), patch.object(d, 'wan_interface', return_value='eth0'), patch.object(m, 'service') as service:
            sid = 'sub-1234567890abcdef'
            url = 'https://example.test/sub'
            config = {**m.DEFAULTS, 'subscriptions': [{'id': sid, 'url': url, 'name': 'Test'}], 'active_subscription': '', 'test_target': 'github'}
            m.atomic_json(m.DATA / 'settings.json', config)
            nodes, _ = parse_subscription('trojan://secret@example.test:443')
            cache = {'nodes': nodes, 'updated': 123, 'source_hash': d.hashlib.sha256(url.encode()).hexdigest()}
            before = (m.DATA / 'settings.json').read_bytes()
            sample = {'name': 'Test', 'ping': {'state': 'no_reply'}, 'tcping': {'state': 'ok', 'ms': 50}, 'url_test': {'state': 'ok', 'ms': 120, 'http_code': 200}}
            with patch.object(m, 'fetch_subscription', return_value=cache), patch.object(d, 'test_node', return_value=sample):
                d.test_all(config)
            self.assertEqual((m.DATA / 'settings.json').read_bytes(), before)
            self.assertEqual(m.read_json(m.DATA / 'tests.json')['entries'][sid]['url_test']['ms'], 120)
            self.assertEqual(m.settings()['active_subscription'], '')
            service.assert_not_called()
            self.assertEqual(m.subscription_tests({'id': sid, 'url': url}, {**cache, 'updated': 456}), {})

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY to validate isolated tests')
    def test_isolated_test_configs_are_valid_and_never_capture_router_traffic(self):
        nodes, _ = parse_subscription('trojan://secret@127.0.0.1:443')
        for mode, value in [('default', ''), ('custom', '9.9.9.9'), ('custom', '94.140.14.14'), ('google', '')]:
            candidate = d.isolated_config({'nodes': nodes}, nodes[0]['id'], {**m.DEFAULTS, 'dns_mode': mode, 'custom_dns': value}, 29080, 'lo0' if sys.platform == 'darwin' else 'lo')
            self.assertEqual(candidate['inbounds'], [{'type': 'mixed', 'tag': 'health-in', 'listen': '127.0.0.1', 'listen_port': 29080}])
            self.assertFalse(any(item['type'] == 'urltest' for item in candidate['outbounds']))
            self.assertEqual(candidate['outbounds'][0]['outbounds'], [nodes[0]['id']])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(candidate))
                result = subprocess.run([os.environ['SING_BOX_TEST_BINARY'], 'check', '-c', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY for actual proxy URL testing')
    def test_url_test_uses_selected_proxy_and_distinguishes_site_restrictions(self):
        # Entirely local: real TLS website, real Shadowsocks server, real core
        # client, no TUN and no external services. Wrong credentials must fail.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            certificate, key = base / 'ca.pem', base / 'key.pem'
            result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(certificate),
                                     '-days', '1', '-subj', '/CN=Nava Test', '-addext', 'subjectAltName=IP:127.0.0.1'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            code, hits = [204], []
            class Website(http.server.BaseHTTPRequestHandler):
                def do_HEAD(self):
                    hits.append(True)
                    self.send_response(code[0])
                    self.end_headers()
                def log_message(self, *_):
                    pass
            website = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Website)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(str(certificate), str(key))
            website.socket = tls.wrap_socket(website.socket, server_side=True)
            thread = threading.Thread(target=website.serve_forever, daemon=True)
            thread.start()
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                proxy_port = reservation.getsockname()[1]
            server_config = {'inbounds': [{'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': proxy_port,
                                          'method': 'aes-128-gcm', 'password': 'correct-password'}],
                             'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
            server_path = base / 'server.json'
            server_path.write_text(json.dumps(server_config))
            server = subprocess.Popen([os.environ['SING_BOX_TEST_BINARY'], 'run', '-c', str(server_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(('127.0.0.1', proxy_port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                nodes, _ = parse_subscription(json.dumps({'outbounds': [{'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': proxy_port,
                                                                        'method': 'aes-128-gcm', 'password': 'correct-password'}]}))
                with patch.object(m, 'RUN', base), patch.object(m, 'CORE', Path(os.environ['SING_BOX_TEST_BINARY'])), patch.dict(os.environ, {'CURL_CA_BUNDLE': str(certificate)}), patch.dict(d.TARGETS, {'google': ('Local test', 'https://127.0.0.1:%d/' % website.server_port)}):
                    interface = 'lo0' if sys.platform == 'darwin' else 'lo'
                    success = d.url_test({'nodes': nodes}, nodes[0], m.DEFAULTS, 'google', interface)
                    self.assertEqual(success['state'], 'ok', success)
                    self.assertEqual(success['http_code'], 204)
                    code[0] = 403
                    restricted = d.url_test({'nodes': nodes}, nodes[0], m.DEFAULTS, 'google', interface)
                    self.assertEqual(restricted['state'], 'restricted', restricted)
                    before = len(hits)
                    nodes[0]['outbound']['password'] = 'wrong-password'
                    failed = d.url_test({'nodes': nodes}, nodes[0], m.DEFAULTS, 'google', interface)
                    self.assertEqual(failed['state'], 'failed', failed)
                    self.assertEqual(len(hits), before, 'The request bypassed the chosen proxy.')
            finally:
                server.terminate()
                server.communicate(timeout=5)
                website.shutdown()
                website.server_close()
                thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
