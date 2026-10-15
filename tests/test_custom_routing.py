"""Custom route input, persistence and RPC payload boundaries."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'luci-app-nava/root/usr/lib/nava'))
import manager as m
import routing as r
from subscription import NavaError,parse_subscription

class CustomRoutingTests(unittest.TestCase):
    def test_ip_and_domain_canonicalization_duplicates_and_unicode(self):
        result=r.validate_custom({'direct_ips':'198.51.100.8\n198.51.100.8/32\n2001:db8::1\n198.51.100.78/24',
                                 'direct_domains':'Example.COM.\n*.example.com\nbücher.example\n\n'})
        self.assertEqual(result['direct_ips'],'198.51.100.8\n2001:db8::1\n198.51.100.0/24')
        self.assertEqual(result['direct_domains'],'example.com\nxn--bcher-kva.example')
        self.assertEqual(result['vpn_domains'],'')

    def test_invalid_line_identifies_the_field_and_line_without_echoing_it(self):
        for text,kind in [('1.2.3.999','ip'),('192.0.2.1:443','ip'),('fe80::1%eth0','ip'),('https://secret.example/private-token','domain'),('example.com:443','domain'),('192.0.2.1','domain'),('bad..example','domain')]:
            with self.subTest(text=text),self.assertRaises(NavaError) as raised:
                r.parse_custom('valid.example\n'+text if kind=='domain' else '192.0.2.1\n'+text,'VPN destinations',kind)
            self.assertIn('VPN destinations: line 2',str(raised.exception))
            self.assertNotIn(text,str(raised.exception))

    def test_entry_and_byte_limits_are_enforced(self):
        with self.assertRaisesRegex(NavaError,'256'):
            r.parse_custom('\n'.join('d%d.example'%i for i in range(257)),'Domains','domain')
        with self.assertRaisesRegex(NavaError,'8 KB'):
            r.parse_custom('x'*8193,'Domains','domain')
        with self.assertRaises(NavaError):r.parse_custom(None,'Domains','domain')

    def test_invalid_custom_entry_cannot_be_saved(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'DATA',Path(directory)),patch.object(m,'service') as service:
            m.atomic_json(m.DATA/'settings.json',m.DEFAULTS)
            before=(m.DATA/'settings.json').read_bytes()
            with self.assertRaisesRegex(NavaError,'Direct domains'):
                m.validate_settings({'action':'save_routing','routing_enabled':False,'ip_source':'ir','domain_source':'ir','direct_domains':'https://example.com/path'})
            self.assertEqual((m.DATA/'settings.json').read_bytes(),before)
            service.assert_not_called()

    def test_custom_does_not_require_country_lists_or_define_dns(self):
        nodes,_=parse_subscription('trojan://fixture@203.0.113.8:443')
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'DATA',Path(directory)):
            config=m.connection_config({**m.DEFAULTS,'routing':{'enabled':False,'direct_domains':'direct.example','vpn_ips':'203.0.113.0/24'}},{'nodes':nodes})
        self.assertNotIn('rule_set',config['route'])
        self.assertNotIn('dns',config)
        self.assertNotIn('default_domain_resolver',config['route'])
        self.assertEqual(config['route']['final'],'proxy')
        self.assertEqual(config['inbounds'][0]['dns_mode'],'disabled')
        self.assertIn({'domain_suffix':['direct.example'],'action':'route','outbound':'direct'},config['route']['rules'])

    def test_all_four_fields_cross_old_rpc_limit_and_survive_reading(self):
        ips='\n'.join('2001:db8:abcd:1234:5678:abcd:ffff:%x'%i for i in range(180))
        domains='\n'.join('destination-%03d.custom-routing.example'%i for i in range(180))
        params={'action':'save_routing','routing_enabled':False,'ip_source':'ir','domain_source':'ir',
                'direct_ips':ips,'vpn_ips':ips,'direct_domains':domains,'vpn_domains':domains}
        raw=json.dumps(params).encode();self.assertGreater(len(raw),16384)
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'DATA',Path(directory)):
            validated=m.validate_settings(params)
            self.assertEqual(len(validated['routing']['direct_domains'].splitlines()),180)
        previous=os.umask(0o077)
        try:
            with patch.object(sys,'argv',['manager.py','call','action']),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(raw))),patch.object(sys,'stdout',io.StringIO()),patch.object(m,'enqueue',return_value={'ok':True}) as enqueue:
                m.main();self.assertEqual(enqueue.call_args.args[0],params)
        finally:os.umask(previous)
