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
from subscription import NavaError, build_config, parse_subscription_bundle


class SubscriptionDNSRuleSetTests(unittest.TestCase):
    def source(self):
        return {'dns': {'servers': [{'type': 'udp', 'tag': 'original', 'server': '9.9.9.9'}],
                        'rules': [{'type': 'logical', 'mode': 'or', 'rules': [
                            {'rule_set': 'provider-domains'}, {'domain': 'example.test'}],
                            'action': 'route', 'server': 'original'}], 'final': 'original'},
                'route': {'default_domain_resolver': 'original', 'rule_set': [
                    {'type': 'inline', 'tag': 'provider-domains', 'rules': [{'domain_suffix': '.example.test'}]},
                    {'type': 'inline', 'tag': 'unused-country-ips', 'rules': [{'ip_cidr': '203.0.113.0/24'}]}],
                    'rules': [{'rule_set': 'unused-country-ips', 'outbound': 'direct'}]},
                'outbounds': [{'type': 'trojan', 'tag': 'node', 'server': '203.0.113.8', 'server_port': 443,
                               'password': 'fixture-secret', 'tls': {'enabled': True}}]}

    def compile(self, source, mode='default'):
        nodes, _, dns, context = parse_subscription_bundle(json.dumps(source), include_context=True)
        return build_config(nodes, dns_mode=mode, custom_dns='94.140.14.14', subscription_dns=dns, subscription_context=context)

    def test_default_ignores_remote_inline_and_missing_dns_dependencies(self):
        for definitions in (self.source()['route']['rule_set'], [],
                            [{'type':'remote','tag':'provider-domains','url':'https://example.test/rules.srs'}]):
            source=self.source(); source['route']['rule_set']=definitions
            original=copy.deepcopy(source)
            config=self.compile(source)
            self.assertNotIn('dns',config)
            self.assertNotIn('rule_set',config['route'])
            self.assertNotIn('http_clients',config)
            self.assertEqual(source,original)

    def test_dns_only_files_and_clients_are_not_imported(self):
        source=self.source()
        source['route']['rule_set']=[{'type':'local','tag':'provider-domains','path':'/etc/shadow'}]
        source['http_clients']=[{'tag':'private-fetch','detour':'fetch-direct'}]
        source['outbounds'].append({'type':'direct','tag':'fetch-direct'})
        config=self.compile(source)
        self.assertNotIn('dns',config)
        self.assertNotIn('http_clients',config)
        self.assertNotIn('fetch-direct',{o['tag'] for o in config['outbounds']})
        self.assertEqual(self.compile(source,'custom')['dns']['final'],'custom-dns-1')

    def test_default_does_not_redownload_old_dns_dependency_cache(self):
        nodes,_,dns,_=parse_subscription_bundle(json.dumps(self.source()),include_context=True)
        url='https://example.test/subscription';sid=m._subscription_id(url)
        config={**m.DEFAULTS,'subscription_url':url,'active_subscription':sid}
        cache={'nodes':nodes,'dns':dns,'dns_context':{'outbounds':[]},'source_hash':hashlib.sha256(url.encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            data=Path(directory);core=data/'core';core.touch()
            with patch.object(m,'DATA',data),patch.object(m,'RUN',data),patch.object(m,'CORE',core),patch.object(m,'preflight'),patch.object(m,'fetch_subscription') as fetch,patch.object(m,'activate',return_value=False):
                m.save_cache(config,cache)
                m.execute('connect',config)
                fetch.assert_not_called()

    @unittest.skipUnless(os.environ.get('SING_BOX_TEST_BINARY'), 'Official core not provided')
    def test_default_without_dns_dependencies_is_accepted_by_official_core(self):
        inline = self.source(); remote = self.source()
        remote['route']['rule_set'] = [{'type': 'remote', 'tag': ['provider-domains', 'unused-country-ips'],
                                       'url': 'https://example.test/{tag}.srs', 'format': 'binary', 'http_client': 'fetch'}]
        remote['http_clients'] = [{'tag': 'fetch', 'detour': 'direct'}]
        for source in (inline, remote):
            config = self.compile(source)
            if sys.platform == 'darwin':
                config['inbounds'][0]['auto_redirect'] = False
                config['inbounds'][0]['interface_name'] = 'utun88'
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'check.json'; path.write_text(json.dumps(config))
                result = subprocess.run([os.environ['SING_BOX_TEST_BINARY'], 'check', '-c', str(path)], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
