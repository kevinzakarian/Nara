import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
import network_cleanup as net


class FullIPTests(unittest.TestCase):
    def test_manager_uses_installed_full_ip_even_when_path_ip_is_busybox(self):
        args = ['ip', '-j', '-4', 'route', 'show', 'table', 'all']
        with patch.object(m.os, 'access', side_effect=lambda path, mode: path == '/usr/libexec/ip-full'), \
             patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess(args, 0, '[]', '')) as run:
            m.command(args)
        self.assertEqual(run.call_args.args[0], ['/usr/libexec/ip-full', *args[1:]])
        self.assertEqual(args[0], 'ip')

    def test_cleanup_json_inspection_uses_the_same_full_ip_binary(self):
        args = ['ip', '-j', '-6', 'rule', 'show']
        state = [{'priority': 20221, 'fwmark': '0x6e01', 'table': 20220}]
        with patch.object(m.os, 'access', side_effect=lambda path, mode: path == '/usr/libexec/ip-full'), \
             patch.object(net.subprocess, 'run', return_value=subprocess.CompletedProcess(args, 0, json.dumps(state), '')) as run:
            self.assertEqual(net.read_command(args), state)
        self.assertEqual(run.call_args.args[0], ['/usr/libexec/ip-full', *args[1:]])

    def test_full_ip_fallback_preserves_other_commands_and_uses_named_full_binary(self):
        with patch.object(m.os, 'access', return_value=False), patch.object(m.shutil, 'which', return_value='/usr/bin/ip-full'):
            self.assertEqual(m.ip_command(['ip', 'rule', 'show']), ['/usr/bin/ip-full', 'rule', 'show'])
            self.assertEqual(m.ip_command(['nft', '-j', 'list', 'ruleset']), ['nft', '-j', 'list', 'ruleset'])
        with patch.object(m.os, 'access', return_value=False), patch.object(m.shutil, 'which', return_value=None):
            self.assertEqual(m.ip_command(['ip', 'rule', 'show']), ['ip', 'rule', 'show'])


if __name__ == '__main__':
    unittest.main()
