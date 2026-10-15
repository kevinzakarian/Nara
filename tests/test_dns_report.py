import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dns_report', Path(__file__).resolve().parents[1] / 'scripts/dns-report.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class DNSReportTests(unittest.TestCase):
    def test_private_credentials_urls_and_tags_are_not_reported(self):
        secret = 'private-secret-token'
        dns = {'servers': [{'type': 'https', 'tag': secret, 'server': secret + '.example',
                            'path': '/dns-query?token=' + secret, 'detour': secret,
                            'tls': {'certificate': secret}}], 'final': secret,
               'rules': [{'domain': [secret + '.example'], 'server': secret}]}
        runtime = {'dns': dns, 'outbounds': [{'type': 'trojan', 'tag': secret, 'password': secret, 'server': secret + '.example'}]}
        output = reporter.report('1.0.0-14', {'subscription_url': 'https://example/' + secret, 'dns_mode': 'default'},
                                 {'dns': dns, 'nodes': [{'password': secret}]}, runtime, {})
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output['subscription_dns']['final_server'], 1)
        self.assertEqual(output['subscription_dns']['servers'][0]['detour_type'], 'trojan')
        self.assertEqual(output['runtime_dns']['rule_servers'], [1])

    def test_report_distinguishes_saved_dns_from_missing_query_path(self):
        dns = {'servers': [{'type': 'udp', 'tag': 'provider', 'server': '9.9.9.9'}], 'final': 'provider'}
        output = reporter.report('1.0.0-14', {'dns_mode': 'default', 'routing_enabled': True}, {'dns': dns},
                                 {'dns': dns, 'inbounds': [{'type': 'tun', 'dns_mode': 'disabled'}]}, {'state': 'off'})
        self.assertEqual(output['subscription_dns']['servers'][0]['endpoint'], '9.9.9.9')
        self.assertFalse(output['dns_listener_present'])
        self.assertFalse(output['dns_hijack_rule_present'])
        self.assertEqual(output['dnsmasq_forwarding_state'], 'off')

    def test_nested_routing_setting_is_reported(self):
        output = reporter.report('1.0.0-27', {'dns_mode': 'default', 'routing': {'enabled': True}}, {}, {}, {})
        self.assertTrue(output['routing_enabled'])
        self.assertTrue(output['default_dns_unconfigured'])


if __name__ == '__main__':
    unittest.main()
