import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import dns_forwarding as dns
import manager as m
from subscription import NavaError, build_config, parse_subscription


class ForwardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.run = self.base / 'run'
        self.configs = self.base / 'etc'
        self.configs.mkdir()
        self.patches = [patch.object(dns, 'RUN', self.run), patch.object(dns, 'CONFIG_DIR', self.configs)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.temp.cleanup()

    def instance(self, name):
        directory = self.base / ('dnsmasq.' + name + '.d')
        directory.mkdir()
        (self.configs / ('dnsmasq.conf.' + name)).write_text('conf-dir=' + str(directory) + '\nserver=192.168.50.1\n')
        return directory

    def test_multiple_instances_forward_then_restore_without_editing_user_config(self):
        first, second = self.instance('abc'), self.instance('def')
        user = first / 'custom.conf'
        user.write_text('server=/internal.test/192.168.50.2\n')
        before = {path: path.read_bytes() for path in self.configs.glob('*')}
        with patch.object(dns, 'restart') as restart:
            dns.update(True)
            dns.update(True)  # Idempotent, no extra restart.
            self.assertEqual(restart.call_count, 1)
            for directory in (first, second):
                content = (directory / 'nava.conf').read_text()
                self.assertIn('server=/#/127.0.0.1#15353', content)
                self.assertIn('no-resolv', content)
            dns.update(False)
            self.assertEqual(restart.call_count, 2)
        self.assertFalse((first / 'nava.conf').exists())
        self.assertFalse((second / 'nava.conf').exists())
        self.assertEqual(user.read_text(), 'server=/internal.test/192.168.50.2\n')
        self.assertEqual(before, {path: path.read_bytes() for path in self.configs.glob('*')})

    def test_failed_restart_rolls_back_all_files(self):
        directory = self.instance('abc')
        with patch.object(dns, 'restart', side_effect=[NavaError('restart failed'), None]):
            with self.assertRaises(NavaError):
                dns.update(True)
        self.assertFalse((directory / 'nava.conf').exists())
        self.assertFalse((self.run / 'dns-files.json').exists())

    def test_collision_preserves_unowned_file(self):
        directory = self.instance('abc')
        (directory / 'nava.conf').write_text('server=8.8.8.8\n')
        with patch.object(dns, 'restart') as restart:
            with self.assertRaises(NavaError):
                dns.update(True)
        restart.assert_not_called()
        self.assertEqual((directory / 'nava.conf').read_text(), 'server=8.8.8.8\n')

    def test_stopped_watcher_cannot_remove_new_connection_forwarding(self):
        directory = self.instance('abc')
        old_generation = dns.arm()
        with patch.object(dns, 'restart') as restart:
            dns.update(True, old_generation)
            new_generation = dns.arm()
            dns.update(True, new_generation)
            self.assertFalse(dns.update(False, old_generation))
            self.assertTrue((directory / 'nava.conf').exists())
            self.assertFalse(dns.update(True, old_generation))
            self.assertEqual(restart.call_count, 1)
            dns.status('ready', generation=new_generation)
            dns.status('error', 'Old failure', old_generation)
            self.assertEqual(m.read_json(self.run / 'dns-status.json')['state'], 'ready')
            dns.update(False, new_generation)

    def test_stop_recovers_owned_file_without_a_saved_manifest(self):
        directory = self.instance('orphan')
        (directory / 'nava.conf').write_text(dns.CONTENT)
        with patch.object(dns, 'restart') as restart:
            dns.update(False)
        restart.assert_called_once()
        self.assertFalse((directory / 'nava.conf').exists())

    def test_stop_retry_never_restores_forwarding_to_a_dead_listener(self):
        directory = self.instance('abc')
        with patch.object(dns, 'restart'):
            dns.update(True)
        with patch.object(dns, 'restart', side_effect=[NavaError('restart failed'), None]):
            self.assertTrue(dns.update(False))
        self.assertFalse((directory / 'nava.conf').exists())

    def test_failed_stop_reload_does_not_resurrect_dead_listener(self):
        directory = self.instance('abc')
        with patch.object(dns, 'restart'):
            dns.update(True)
        with patch.object(dns, 'restart', side_effect=NavaError('restart failed')):
            with self.assertRaisesRegex(NavaError, 'could not reload'):
                dns.update(False)
        self.assertFalse((directory / 'nava.conf').exists())
        # The record remains available to retry, although the file is gone.
        self.assertEqual(m.read_json(self.run / 'dns-files.json'), [str(directory / 'nava.conf')])

    def test_missing_dnsmasq_cannot_silently_ignore_override(self):
        with self.assertRaises(NavaError):
            dns.update(True)
        with patch.object(dns, 'restart') as restart:
            dns.update(False)
        restart.assert_not_called()

    def test_default_never_injects_dns_listener_or_override(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        default = build_config(nodes)
        self.assertNotIn('dns', default)
        self.assertFalse(any(item['tag'] == 'nava-dns-in' for item in default['inbounds']))
        for ip in ('9.9.9.9', '94.140.14.14'):
            custom = build_config(nodes, dns_mode='custom', custom_dns=ip)
            self.assertEqual(custom['dns']['servers'][0]['server'], ip)
            listener = next(item for item in custom['inbounds'] if item['tag'] == 'nava-dns-in')
            self.assertEqual(listener['listen'], '127.0.0.1')
            self.assertEqual(listener['listen_port'], 15353)
            self.assertEqual(custom['route']['rules'][0]['action'], 'hijack-dns')

    def test_hostname_bootstrap_is_pinned_before_forwarding(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        custom = build_config(nodes, dns_mode='custom', custom_dns='https://dns.quad9.net/dns-query')
        with patch.object(m.socket, 'getaddrinfo', return_value=[(2, 2, 17, '', ('9.9.9.9', 53))]):
            m.prepare_dns_bootstrap(custom)
        bootstrap = next(server for server in custom['dns']['servers'] if server['tag'] == 'bootstrap')
        self.assertEqual(bootstrap['server'], '9.9.9.9')
        self.assertEqual(bootstrap['tls']['server_name'], 'dns.quad9.net')
        self.assertNotIn('domain_resolver', bootstrap)

    def test_forwarding_failure_restores_old_connection(self):
        data = self.base / 'data'
        data.mkdir()
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        with patch.object(m, 'DATA', data), patch.object(m, 'RUN', self.run), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'running', return_value=True), patch.object(m, 'wait_dns', side_effect=NavaError('Failed DNS')), patch.object(m, 'service') as service:
            m.atomic_json(data / 'config.json', {'old': True})
            with self.assertRaises(NavaError):
                m.activate({**m.DEFAULTS, 'dns_mode': 'custom', 'custom_dns': '9.9.9.9'}, {'nodes': nodes})
            self.assertEqual(m.read_json(data / 'config.json'), {'old': True})
            self.assertEqual([call.args[0] for call in service.call_args_list], ['stop', 'start', 'stop', 'start'])
            self.assertFalse((data / 'settings.json').exists())


if __name__ == '__main__':
    unittest.main()
