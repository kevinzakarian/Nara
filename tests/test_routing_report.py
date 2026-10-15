import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('routing_report', Path(__file__).resolve().parents[1] / 'scripts/routing-report.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class RoutingReportTests(unittest.TestCase):
    def test_report_is_read_only_and_distinguishes_stopped_core_from_residual_rules(self):
        secret = 'private-subscription-token'
        settings = {'routing_enabled': True, 'subscription_url': 'https://example/' + secret}
        runtime = {'outbounds': [{'password': secret}], 'inbounds': [{'type': 'tun', 'interface_name': 'nava0', 'auto_route': True}]}
        services = {'nava': {'instances': {'core': {'running': False}, 'dns': {'running': True}}},
                    'passwall': {'instances': {secret: {'running': True, 'command': [secret]}}}}
        nft = {'nftables': [{'table': {'family': 'inet', 'name': 'sing-box'}},
                            {'rule': {'table': 'sing-box', 'expr': [{'match': {'right': 'nava0'}}]}}]}
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args == ['ubus', 'call', 'service', 'list', '{}']:
                output = json.dumps(services)
            elif args == ['nft', '-j', 'list', 'ruleset']:
                output = json.dumps(nft)
            elif args == ['ip', '-j', 'link', 'show']:
                output = '[]'
            elif args == ['opkg', 'list-installed', 'luci-app-nava']:
                output = 'luci-app-nava - 1.0.0-17\n'
            elif args in [['ip', family, *command] for family in ('-4', '-6')
                         for command in (['rule', 'show'], ['route', 'show', 'table', 'all'])]:
                output = '0: from all lookup local\n'
            else:
                self.fail('Unexpected command: ' + str(args))
            return subprocess.CompletedProcess(args, 0, output, '')
        def read(path):
            if str(path).endswith('settings.json'):
                return settings
            if str(path).endswith('config.json'):
                return runtime
            if str(path).endswith('job.json'):
                return {'action': 'save_routing', 'state': 'done', 'message': secret}
            return {}
        def source(path):
            if str(path).endswith('manager.py'):
                return b'APP_VERSION = "1.0.0-17"\nif action == "save_routing" and not was_running:\n'
            raise OSError('unavailable')
        with patch.object(reporter, 'read_json', side_effect=read), patch.object(reporter.subprocess, 'run', side_effect=run), \
             patch.object(Path, 'read_bytes', source), patch.object(Path, 'read_text', side_effect=OSError), \
             patch.object(Path, 'glob', return_value=[]), patch.object(reporter.shutil, 'which', return_value='/usr/sbin/conntrack'):
            output = reporter.report()
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output['installed_package_version'], '1.0.0-17')
        self.assertTrue(output['offline_save_guard_present'])
        self.assertFalse(output['service_instances']['nava'][0]['running'])
        self.assertEqual(output['nava_core_process_count'], 0)
        self.assertTrue(output['sing_box_table_present'])
        self.assertEqual(output['sing_box_rules_referencing_nava0'], 1)
        self.assertFalse(output['tun_interface_present'])
        self.assertEqual(len(calls), 8)

    def test_firewall_fingerprints_ignore_traffic_counters_but_detect_passwall_rule_changes(self):
        def entries(packets, port):
            return [{'table': {'family': 'inet', 'name': 'passwall2'}}, {'rule': {
                'family': 'inet', 'table': 'passwall2', 'chain': 'PSW2',
                'expr': [{'counter': {'packets': packets, 'bytes': packets * 50}}, {'redirect': {'port': port}}]}}]
        before = reporter.nft_summary(entries(10, 1053))
        self.assertEqual(before, reporter.nft_summary(entries(200, 1053)))
        self.assertNotEqual(before, reporter.nft_summary(entries(200, 2053)))
        self.assertTrue(before['passwall2']['present'])
        self.assertFalse(before['sing-box']['present'])

    def test_watch_captures_the_actual_button_operation_without_invoking_it(self):
        before = {'last_operation': {'action': 'disconnect', 'updated': 1}, 'firewall_tables': {'passwall2': {'rules': 2}}}
        after = {'last_operation': {'action': 'save_routing', 'updated': 2}, 'firewall_tables': {'passwall2': {'rules': 3}}}
        with patch.object(reporter, 'report', side_effect=[before, after]), \
             patch.object(reporter, 'read_json', return_value={'action': 'save_routing', 'state': 'done', 'updated': 2}), \
             patch.object(reporter.time, 'sleep'), patch('builtins.print') as output:
            reporter.watch()
        captured = json.loads(output.call_args.args[0])
        self.assertIn('firewall_tables', captured['changed_sections'])
        self.assertEqual(captured['before'], before)
        self.assertEqual(captured['after'], after)

    def test_set_expiry_countdown_is_not_reported_as_a_configuration_change(self):
        def entries(expires, address):
            return [{'table': {'family': 'inet', 'name': 'passwall2'}}, {'set': {
                'family': 'inet', 'table': 'passwall2', 'name': 'psw2_direct',
                'elem': [{'elem': {'val': address, 'timeout': 3600, 'expires': expires}}]}}]
        before = reporter.nft_summary(entries(3590, '192.0.2.1'))
        self.assertEqual(before, reporter.nft_summary(entries(3588, '192.0.2.1')))
        self.assertNotEqual(before, reporter.nft_summary(entries(3588, '192.0.2.2')))


if __name__ == '__main__':
    unittest.main()
