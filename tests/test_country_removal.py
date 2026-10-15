import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, build_config, parse_subscription


class CountryRemovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        handle = patch.object(m, 'DATA', self.data)
        handle.start(); self.addCleanup(handle.stop)
        self.nodes, _ = parse_subscription('trojan://secret@203.0.113.8:443')

    def test_upgrade_removes_legacy_preferences_and_rules_preserving_dns_and_servers(self):
        saved = {**m.DEFAULTS, 'routing_enabled': True, 'geoip_source': 'ir', 'geosite_source': 'ru',
                 'skin': 'orange', 'dns_mode': 'custom', 'custom_dns': '9.9.9.9',
                 'subscriptions': [{'id': 'sub-example', 'name': 'Example', 'url': 'https://example.test/private'}]}
        m.atomic_json(self.data / 'settings.json', saved)
        config = build_config(self.nodes, dns_mode='custom', custom_dns='9.9.9.9')
        expected = copy.deepcopy(config)
        config['route']['rule_set'] = [{'type': 'local', 'tag': 'nava-ir-ip', 'path': '/etc/nava/rules/generation-old/ir-ip.srs'}]
        config['route']['rules'].extend([
            {'inbound': ['health-in'], 'action': 'route', 'outbound': 'proxy'},
            {'inbound': ['tun-in'], 'action': 'sniff', 'sniffer': ['http', 'tls', 'quic']},
            {'rule_set': ['nava-ir-ip'], 'action': 'route', 'outbound': 'direct'}])
        m.atomic_json(self.data / 'config.json', config)
        m.atomic_json(self.data / 'routing.json', {'files': {}})
        (self.data / 'rules/generation-old').mkdir(parents=True)
        (self.data / 'rules/generation-old/ir-ip.srs').write_bytes(b'old-list')
        with patch.object(m, 'command') as command, patch.object(m, 'service') as service:
            m.migrate_country_removal()
            command.assert_not_called(); service.assert_not_called()
        self.assertEqual(m.read_json(self.data / 'config.json'), expected)
        for key in ('routing_enabled', 'geoip_source', 'geosite_source'):
            saved.pop(key)
        self.assertEqual(m.read_json(self.data / 'settings.json'), saved)
        self.assertFalse((self.data / 'routing.json').exists())
        self.assertFalse((self.data / 'rules').exists())
        before = (self.data / 'config.json').read_bytes()
        m.migrate_country_removal()
        self.assertEqual((self.data / 'config.json').read_bytes(), before)

    def test_upgrade_preserves_unrelated_rule_sets(self):
        config = build_config(self.nodes)
        foreign = {'type': 'inline', 'tag': 'provider', 'rules': [{'domain': ['example.test']}]}
        foreign_rule = {'rule_set': ['provider'], 'action': 'reject'}
        config['route']['rule_set'] = [foreign, {'type': 'local', 'tag': 'nava-ru-domain', 'path': '/old.srs'}]
        config['route']['rules'].extend([foreign_rule, {'rule_set': ['nava-ru-domain'], 'action': 'route', 'outbound': 'direct'}])
        m.atomic_json(self.data / 'config.json', config)
        m.migrate_country_removal()
        migrated = m.read_json(self.data / 'config.json')
        self.assertEqual(migrated['route']['rule_set'], [foreign])
        self.assertIn(foreign_rule, migrated['route']['rules'])
        self.assertNotIn('dns', migrated)

    def test_legacy_flat_settings_cannot_reenable_restored_feature(self):
        m.atomic_json(self.data / 'settings.json', {**m.DEFAULTS, 'routing_enabled': True, 'geoip_source': 'cn'})
        self.assertNotIn('routing_enabled', m.settings())
        self.assertFalse(m.settings()['routing']['enabled'])

    def test_connect_ignores_missing_old_country_lists(self):
        core = self.data / 'core'; core.touch()
        config = {**m.DEFAULTS, 'routing_enabled': True}
        cache = {'nodes': self.nodes}
        with patch.object(m, 'CORE', core), patch.object(m, 'preflight'), patch.object(m, 'fetch_subscription', return_value=cache), patch.object(m, 'activate', return_value=False) as activate, patch.object(m, 'probe', return_value=True), patch.object(m, 'download') as download:
            self.assertEqual(m.execute('connect', config), 'Connected. Internet access verified.')
            activate.assert_called_once_with(config, cache)
            download.assert_not_called()

    def test_unreadable_runtime_is_not_overwritten(self):
        path = self.data / 'config.json'; path.write_text('invalid')
        with self.assertRaises(ValueError):
            m.migrate_country_removal()
        self.assertEqual(path.read_text(), 'invalid')

    def test_status_displays_restored_routing_operation(self):
        with patch.object(m, 'RUN', self.data), patch.object(m, 'busy', return_value=False), patch.object(m, 'running', return_value=False):
            m.atomic_json(self.data / 'job.json', {'action': 'save_routing', 'state': 'done', 'message': 'Routing settings saved.'})
            state = m.status()
            self.assertEqual(state['job']['action'], 'save_routing')
            self.assertIn('routing', state)


if __name__ == '__main__':
    unittest.main()
