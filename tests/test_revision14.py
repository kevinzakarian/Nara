"""Default DNS preserves the original resolver and ordinary proxy routing."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
from subscription import build_config, parse_subscription


class DefaultRoutingDNSTests(unittest.TestCase):
    def setUp(self):
        self.nodes, _ = parse_subscription('trojan://secret@203.0.113.8:443')
    def test_default_ignores_profile_engine_and_disables_implicit_hijack(self):
        provider = {'servers': [{'type': 'udp', 'tag': 'original', 'server': '9.9.9.9'}], 'final': 'original'}
        for mode in ('default', '', None):
            for dns in (None, provider):
                config = build_config(self.nodes, dns_mode=mode, subscription_dns=dns)
                self.assertEqual(config['inbounds'][0]['dns_mode'], 'disabled')
                self.assertNotIn('dns', config)
                self.assertEqual(any(rule.get('action') == 'hijack-dns' for rule in config['route']['rules']), False)
                self.assertEqual(any(item.get('tag') == 'nava-dns-in' for item in config['inbounds']), False)

    def test_only_explicit_dns_override_precedes_ipv6_rules(self):
        for mode in ('default', 'cloudflare', 'google', 'opendns', 'custom'):
            config = build_config(self.nodes, dns_mode=mode, custom_dns='9.9.9.9', ipv6=False)
            rules = config['route']['rules']
            self.assertFalse(any(rule.get('port') == [53, 853] for rule in rules))
            if mode == 'default':
                self.assertFalse(any(rule.get('action') == 'hijack-dns' for rule in rules))
            else:
                self.assertEqual(rules[0], {'port': 53, 'action': 'hijack-dns'})
                self.assertLess(next(i for i, rule in enumerate(rules) if rule.get('ip_version') == 6), next(i for i, rule in enumerate(rules) if rule.get('ip_is_private')))

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Set SING_BOX_TEST_BINARY for real DNS transport verification')
    def test_real_default_dns_keeps_original_destination_and_normal_proxy_routing(self):
        # No host TUN or external traffic. Two real local Shadowsocks inbounds
        # translate the TEST-NET resolver to different loopback responders.
        # Default follows regular proxy routing, with no DNS-only override.
        # Unlike the previous test, proxy and direct do NOT share a resolver.
        core = os.environ['SING_BOX_TEST_BINARY']
        stop = threading.Event()
        responses = {'proxy': '192.0.2.21', 'direct': '192.0.2.99'}
        question = b'\x04nara\x07example\x00' + struct.pack('!HH', 1, 1)
        query = struct.pack('!6H', 789, 0x0100, 1, 0, 0, 0) + question
        threads, sockets, received = [], [], {'proxy': [], 'direct': []}
        def answer(packet, which):
            received[which].append(packet)
            return packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + packet[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(responses[which])
        def udp_server(sock, which):
            while not stop.is_set():
                try:
                    packet, peer = sock.recvfrom(4096)
                    sock.sendto(answer(packet, which), peer)
                except socket.timeout:
                    continue
        def tcp_server(sock, which):
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(2)
                    try:
                        size = struct.unpack('!H', conn.recv(2))[0]
                        packet = b''
                        while len(packet) < size:
                            part = conn.recv(size - len(packet))
                            if not part:
                                break
                            packet += part
                        if len(packet) == size:
                            reply = answer(packet, which)
                            conn.sendall(struct.pack('!H', len(reply)) + reply)
                    except (OSError, struct.error):
                        pass
        def free_port():
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                return reservation.getsockname()[1]
        try:
            resolver_ports = {}
            for which in responses:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
                tcp = socket.socket(); tcp.bind(udp.getsockname()); tcp.listen(); tcp.settimeout(.2)
                sockets.extend([udp, tcp]); resolver_ports[which] = udp.getsockname()[1]
                for handler, sock in [(udp_server, udp), (tcp_server, tcp)]:
                    thread = threading.Thread(target=handler, args=(sock, which), daemon=True)
                    thread.start(); threads.append(thread)
            with tempfile.TemporaryDirectory() as directory:
                ports = {which: free_port() for which in responses}
                server_config = {'log': {'level': 'error'}, 'inbounds': [
                    {'type': 'shadowsocks', 'tag': which, 'listen': '127.0.0.1', 'listen_port': ports[which],
                     'method': 'aes-128-gcm', 'password': 'local-test-only'} for which in responses],
                    'outbounds': [{'type': 'direct', 'tag': 'local'}],
                    'route': {'rules': [{'inbound': [which], 'action': 'route', 'outbound': 'local',
                                         'override_address': '127.0.0.1', 'override_port': resolver_ports[which]} for which in responses]}}
                server_path = Path(directory) / 'server.json'; server_path.write_text(json.dumps(server_config))
                server = subprocess.Popen([core, 'run', '-c', str(server_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        try:
                            with socket.create_connection(('127.0.0.1', ports['proxy']), timeout=.2):
                                break
                        except OSError:
                            time.sleep(.05)
                    for legacy in (False,):
                        for transport in ('udp', 'tcp'):
                            with self.subTest(legacy=legacy, transport=transport):
                                listener = free_port()
                                config = build_config(self.nodes)
                                if legacy:
                                    config['route']['rules'] = [rule for rule in config['route']['rules'] if rule.get('port') != [53, 853]]
                                config['inbounds'] = [{'type': 'direct', 'tag': 'tun-in', 'listen': '127.0.0.1', 'listen_port': listener,
                                                       'override_address': '198.51.100.53', 'override_port': 53}]
                                config['outbounds'] = [{'type': 'shadowsocks', 'tag': which, 'server': '127.0.0.1', 'server_port': ports[which],
                                                        'method': 'aes-128-gcm', 'password': 'local-test-only'} for which in responses]
                                config['log']['level'] = 'debug'
                                path = Path(directory) / 'client.json'; path.write_text(json.dumps(config))
                                client = subprocess.Popen([core, '--disable-color', 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                                response = None
                                try:
                                    deadline = time.monotonic() + 7
                                    while response is None and time.monotonic() < deadline and client.poll() is None:
                                        try:
                                            if transport == 'udp':
                                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as request:
                                                    request.settimeout(.3); request.sendto(query, ('127.0.0.1', listener))
                                                    response, _ = request.recvfrom(4096)
                                            else:
                                                with socket.create_connection(('127.0.0.1', listener), timeout=.4) as request:
                                                    request.settimeout(4)
                                                    request.sendall(struct.pack('!H', len(query)) + query)
                                                    size = struct.unpack('!H', request.recv(2))[0]
                                                    response = b''
                                                    while len(response) < size:
                                                        part = request.recv(size - len(response))
                                                        if not part:
                                                            break
                                                        response += part
                                        except (OSError, struct.error):
                                            time.sleep(.05)
                                finally:
                                    client.terminate(); _, logs = client.communicate(timeout=5)
                                self.assertIsNotNone(response, logs.decode())
                                which = 'proxy'
                                self.assertEqual(response[-4:], socket.inet_aton(responses[which]), logs.decode())
                                self.assertTrue(received[which])
                finally:
                    server.terminate(); server.communicate(timeout=5)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=3)
            for sock in sockets:
                sock.close()


if __name__ == '__main__':
    unittest.main()
