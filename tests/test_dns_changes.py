import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, parse_subscription_bundle


class DNSChangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        for name in ('DATA', 'RUN'):
            handle = patch.object(m, name, self.data); handle.start(); self.addCleanup(handle.stop)
        source = {'route': {'default_domain_resolver': 'local'}, 'dns': {'servers': [
            {'type': 'tcp', 'tag': 'remote', 'server': '8.8.8.8', 'detour': 'group'},
            {'type': 'local', 'tag': 'local'}], 'final': 'remote'},
            'outbounds': [{'type': 'anytls', 'tag': 'node', 'server': '203.0.113.8', 'server_port': 443,
                           'password': 'fixture-password', 'tls': {'enabled': True, 'server_name': 'example.test'}},
                          {'type': 'selector', 'tag': 'group', 'outbounds': ['node'], 'default': 'node'}]}
        nodes, warnings, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        url = 'https://example.test/private-subscription'; sid = m._subscription_id(url)
        self.config = {**m.DEFAULTS, 'subscription_url': url, 'active_subscription': sid,
                       'subscriptions': [{'id': sid, 'name': 'Fixture', 'url': url}]}
        self.cache = {'nodes': nodes, 'dns': dns, 'dns_context': context, 'warnings': warnings,
                      'source_hash': hashlib.sha256(url.encode()).hexdigest()}

    def test_reconnect_uses_unchanged_cached_servers_and_update_is_explicit(self):
        m.save_cache(self.config, self.cache)
        core = self.data / 'core'; core.touch()
        with patch.object(m, 'CORE', core), patch.object(m, 'preflight'), patch.object(m, 'fetch_subscription') as fetch, patch.object(m, 'activate', return_value=False) as activate, patch.object(m, 'probe', return_value=True):
            for mode in ('custom', 'google', 'default', 'custom'):
                config = {**self.config, 'dns_mode': mode, 'custom_dns': '94.140.14.14'}
                m.execute('connect', config)
                self.assertEqual(activate.call_args.args[1], self.cache)
            fetch.assert_not_called()
            config = {**self.config, 'operation_subscription': self.config['active_subscription']}
            fetch.return_value = self.cache
            m.execute('update_subscription', config)
            fetch.assert_called_once()

    def test_changed_link_or_missing_cache_requires_download(self):
        m.save_cache(self.config, self.cache)
        core = self.data / 'core'; core.touch()
        with patch.object(m, 'CORE', core), patch.object(m, 'preflight'), patch.object(m, 'fetch_subscription', return_value=self.cache) as fetch, patch.object(m, 'activate', return_value=False), patch.object(m, 'probe', return_value=True):
            m.execute('connect', {**self.config, 'subscription_url': 'https://example.test/replacement'})
            m.execute('connect', {**self.config, 'active_subscription': 'sub-0000000000000000'})
            self.assertEqual(fetch.call_count, 2)

    def test_repeated_activation_does_not_mutate_subscription_dns_or_credentials(self):
        before = copy.deepcopy(self.cache)
        with patch.object(m, 'running', return_value=True), patch.object(m, 'service'), patch.object(m, 'check_config'), patch.object(m, 'wait_running'), patch.object(m, 'wait_dns'), patch.object(m, 'probe', return_value=True):
            for mode in ['custom', 'cloudflare', 'default', 'google', 'custom', 'opendns', 'default'] * 3:
                config = {**self.config, 'dns_mode': mode, 'custom_dns': '94.140.14.14'}
                m.activate(config, self.cache)
                generated = m.read_json(self.data / 'config.json')
                if mode == 'default':
                    self.assertNotIn('dns', generated)
                    self.assertFalse(any(x.get('tag') == 'nava-dns-in' for x in generated['inbounds']))
                else:
                    self.assertTrue(any(x.get('tag') == 'nava-dns-in' for x in generated['inbounds']))
                    if mode == 'custom':
                        final = generated['dns']['final']
                        self.assertEqual(next(x['server'] for x in generated['dns']['servers'] if x['tag'] == final), '94.140.14.14')
                self.assertEqual(self.cache, before)
                self.assertEqual(m.settings()['dns_mode'], mode)

    def test_dns_validation_errors_are_specific_and_do_not_expose_tags_or_passwords(self):
        result = subprocess.CompletedProcess([], 1, '', 'initialize dns router: dns rule[3]: rule-set not found: PRIVATE-TAG fixture-password')
        with patch.object(m, 'command', return_value=result):
            with self.assertRaises(NavaError) as raised:
                m.check_config(self.data / 'core', self.data / 'config.json')
        error = str(raised.exception)
        self.assertIn('DNS rule 3', error)
        self.assertIn('missing rule set', error)
        self.assertNotIn('PRIVATE-TAG', error)
        self.assertNotIn('fixture-password', error)

    def test_operation_result_identifies_the_requested_dns_without_exposing_the_link(self):
        m.atomic_json(self.data / 'settings.json', self.config)
        with patch.object(m.subprocess, 'Popen'):
            result = m.enqueue({'action': 'connect', 'dns_mode': 'custom', 'custom_dns': '94.140.14.14'})
        job = m.read_json(self.data / 'job.json')
        self.assertRegex(result['operation_id'], r'^[a-f0-9]{32}$')
        self.assertEqual(job['operation_id'], result['operation_id'])
        self.assertEqual(job['requested_dns_mode'], 'custom')
        self.assertEqual(job['requested_subscription_id'], self.config['active_subscription'])
        self.assertNotIn('private-subscription', json.dumps(job))
        m.job_update('error', 'Validation failed.', state='error')
        self.assertEqual(m.read_json(self.data / 'job.json')['operation_id'], result['operation_id'])

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Official core not provided')
    def test_dns_change_sequence_with_official_core(self):
        for mode in ('default', 'custom', 'google', 'custom', 'cloudflare', 'default'):
            generated = m.build_config(self.cache['nodes'], dns_mode=mode, custom_dns='94.140.14.14', subscription_dns=self.cache['dns'], subscription_context=self.cache['dns_context'])
            if sys.platform == 'darwin':
                generated['inbounds'][0]['auto_redirect'] = False
                generated['inbounds'][0]['interface_name'] = 'utun88'
            path = self.data / 'check.json'; path.write_text(json.dumps(generated))
            result = subprocess.run([os.environ['SING_BOX_TEST_BINARY'], 'check', '-c', str(path)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
