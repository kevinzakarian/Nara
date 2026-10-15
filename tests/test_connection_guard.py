import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, parse_subscription


class ConnectionGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name) / 'data'; self.data.mkdir()
        self.run = Path(self.temp.name) / 'run'; self.run.mkdir()
        for name, value in [('DATA', self.data), ('RUN', self.run)]:
            handle = patch.object(m, name, value); handle.start(); self.addCleanup(handle.stop)
        nodes, _ = parse_subscription('trojan://secret@203.0.113.8:443')
        self.cache = {'nodes': nodes}

    def test_proxy_success_does_not_hide_broken_router_path(self):
        def command(args, **kwargs):
            proxy = args[args.index('--proxy') + 1]
            return subprocess.CompletedProcess(args, 0 if proxy else 28, '204' if proxy else '000', '')
        with patch.object(m, 'running', return_value=True), patch.object(m, 'command', side_effect=command):
            self.assertFalse(m.probe())
        health = m.read_json(self.run / 'health.json')
        self.assertTrue(health['proxy_ok']); self.assertFalse(health['tunnel_ok'])

    def test_router_path_cannot_use_an_environment_proxy(self):
        def command(args, **kwargs):
            if not args[args.index('--proxy') + 1]:
                self.assertEqual(args[args.index('--noproxy') + 1], '*')
            self.assertEqual(args[-1], m.TEST_URL)
            return subprocess.CompletedProcess(args, 0, '204', '')
        with patch.object(m, 'running', return_value=True), patch.object(m, 'command', side_effect=command) as run:
            self.assertTrue(m.probe())
            self.assertEqual(run.call_count, 2)

    def test_probe_timeout_is_a_failed_health_result(self):
        with patch.object(m, 'running', return_value=True), patch.object(m, 'command', side_effect=NavaError('timeout')):
            self.assertFalse(m.probe())
        self.assertFalse(m.read_json(self.run / 'health.json')['ok'])

    def test_failed_first_connection_restores_direct_state_and_saved_settings(self):
        old = {'old': True}
        m.atomic_json(self.data / 'config.json', old)
        m.atomic_json(self.data / 'settings.json', m.DEFAULTS)
        with patch.object(m, 'running', return_value=False), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'probe', return_value=False), patch.object(m, 'service') as service:
            with self.assertRaisesRegex(NavaError, 'disconnected to restore direct'):
                m.activate({**m.DEFAULTS, 'dns_mode': 'custom', 'custom_dns': '94.140.14.14'}, self.cache)
        self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop'])
        self.assertEqual(m.read_json(self.data / 'config.json'), old)
        self.assertEqual(m.read_json(self.data / 'settings.json'), m.DEFAULTS)
        self.assertFalse((self.data / 'subscription.json').exists())
        self.assertFalse((self.data / 'config.new.json').exists())

    def test_failed_reconnect_restores_previous_config_and_health(self):
        old = {'old': True}; health = {'ok': True, 'checked': 10}
        m.atomic_json(self.data / 'config.json', old); m.atomic_json(self.run / 'health.json', health)
        def failed():
            m.atomic_json(self.run / 'health.json', {'proxy_ok': True, 'tunnel_ok': False})
            return False
        with patch.object(m, 'running', return_value=True), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'probe', side_effect=failed), patch.object(m, 'service') as service:
            with self.assertRaisesRegex(NavaError, 'router tunnel failed.*previous connection'):
                m.activate(m.DEFAULTS, self.cache)
        self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop', 'start'])
        self.assertEqual(m.read_json(self.data / 'config.json'), old)
        self.assertEqual(m.read_json(self.run / 'health.json'), health)

    def test_success_commits_only_after_both_paths_are_verified(self):
        with patch.object(m, 'running', return_value=False), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'service'), patch.object(m, 'probe', return_value=True) as probe:
            m.activate(m.DEFAULTS, self.cache)
        probe.assert_called_once()
        self.assertEqual(m.read_json(self.data / 'settings.json'), m.DEFAULTS)
        self.assertEqual(m.active_cache(m.DEFAULTS)['nodes'], self.cache['nodes'])

    def test_probe_identifies_a_working_ipv4_path_when_automatic_path_stalls(self):
        def command(args, **kwargs):
            good = bool(args[args.index('--proxy') + 1]) or '--ipv4' in args
            return subprocess.CompletedProcess(args, 0 if good else 28, '204' if good else '000', '')
        with patch.object(m, 'running', return_value=True), patch.object(m, 'command', side_effect=command):
            self.assertFalse(m.probe())
        health = m.read_json(self.run / 'health.json')
        self.assertTrue(health['proxy_ok']); self.assertTrue(health['tunnel_ipv4_ok'])
        self.assertFalse(health['tunnel_ok'])

    def test_ipv6_fallback_preserves_default_dns_and_records_actual_preference(self):
        dns = {'servers': [{'type': 'local', 'tag': 'original'}], 'final': 'original'}
        cache = {**self.cache, 'dns': dns}
        config = {**m.DEFAULTS, 'ipv6': True}
        calls = 0
        def probe():
            nonlocal calls
            calls += 1
            m.atomic_json(self.run / 'health.json', {'proxy_ok': True, 'tunnel_ipv4_ok': True, 'tunnel_ok': calls == 2})
            return calls == 2
        with patch.object(m, 'running', return_value=False), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'service') as service, patch.object(m, 'probe', side_effect=probe):
            self.assertTrue(m.activate(config, cache))
        self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop', 'start', 'disable'])
        saved = m.read_json(self.data / 'config.json')
        self.assertNotIn('dns', saved)
        self.assertEqual(cache['dns'], dns)
        self.assertIn({'ip_version': 6, 'action': 'reject'}, saved['route']['rules'])
        self.assertFalse(m.settings()['ipv6'])
        self.assertTrue(config['ipv6'])
        self.assertFalse(any(x.get('tag') == 'nava-dns-in' for x in saved['inbounds']))

    def test_failed_ipv4_retry_does_not_commit_a_changed_preference(self):
        old = {'old': True}; m.atomic_json(self.data / 'config.json', old)
        m.atomic_json(self.data / 'settings.json', m.DEFAULTS)
        def probe():
            m.atomic_json(self.run / 'health.json', {'proxy_ok': True, 'tunnel_ipv4_ok': True, 'tunnel_ok': False})
            return False
        with patch.object(m, 'running', return_value=False), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'service') as service, patch.object(m, 'probe', side_effect=probe) as checked:
            with self.assertRaises(NavaError):
                m.activate(m.DEFAULTS, self.cache)
        self.assertEqual(checked.call_count, 2)
        self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop', 'start', 'stop'])
        self.assertEqual(m.read_json(self.data / 'config.json'), old)
        self.assertEqual(m.read_json(self.data / 'settings.json'), m.DEFAULTS)


if __name__ == '__main__':
    unittest.main()
