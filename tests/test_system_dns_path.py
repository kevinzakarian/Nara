"""Default adds no DNS engine, upstream discovery or DNS routing exceptions."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import parse_subscription

class NoDefaultDNSPathTests(unittest.TestCase):
    def test_default_does_not_query_or_pin_a_dns_provider(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        nodes[0]['outbound']['domain_resolver'] = 'provider-local'
        cache = {'nodes': nodes, 'dns': {'servers': [{'type': 'local', 'tag': 'provider-local'}]},
                 'dns_context': {'error': 'Missing provider DNS dependency', 'domain_resolver': 'provider-local'}}
        before = copy.deepcopy(cache)
        with patch.object(m, 'prepare_dns_bootstrap') as bootstrap, patch.object(m.socket, 'getaddrinfo') as lookup:
            generated = m.connection_config(m.DEFAULTS, cache)
        bootstrap.assert_not_called(); lookup.assert_not_called()
        self.assertNotIn('dns', generated)
        self.assertNotIn('default_domain_resolver', generated['route'])
        self.assertFalse(any('domain_resolver' in o for o in generated['outbounds']))
        self.assertEqual(generated['inbounds'][0]['route_exclude_address'], ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7'])
        self.assertEqual(cache, before)
        self.assertTrue(generated['inbounds'][0]['auto_route'])
        self.assertTrue(generated['inbounds'][0]['auto_redirect'])
        self.assertEqual(generated['route']['final'], 'proxy')

    def test_explicit_custom_dns_still_uses_the_requested_provider(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        generated = m.connection_config({**m.DEFAULTS, 'dns_mode': 'custom', 'custom_dns': '94.140.14.14'}, {'nodes': nodes})
        final = generated['dns']['final']
        self.assertEqual(next(s['server'] for s in generated['dns']['servers'] if s['tag'] == final), '94.140.14.14')
        self.assertTrue(any(r.get('action') == 'hijack-dns' for r in generated['route']['rules']))
