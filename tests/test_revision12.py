import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, build_config, parse_subscription


class GeneralTests(unittest.TestCase):
    def test_skin_save_preserves_connection_library(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'DATA', Path(directory)):
            url = 'https://example.test/private-subscription'
            sid = m._subscription_id(url)
            saved = {**m.DEFAULTS, 'subscriptions': [{'id': sid, 'name': 'Example', 'url': url}],
                     'subscription_url': url, 'active_subscription': sid, 'selected': 'node-1234567890abcdef',
                     'dns_mode': 'custom', 'custom_dns': '94.140.14.14'}
            m.atomic_json(m.DATA / 'settings.json', saved)
            with patch.object(m, 'service') as service, patch.object(m, 'activate', return_value=False) as activate:
                config = m.validate_settings({'action': 'save_general', 'skin': 'orange', 'dns_mode': 'default', 'subscription_id': ''})
                m.execute('save_general', config)
                self.assertEqual(m.settings(), {**saved, 'skin': 'orange'})
                self.assertEqual(m.read_json(m.DATA / 'settings.json'), {**saved, 'skin': 'orange'})
                service.assert_not_called()
                activate.assert_not_called()
                config = m.validate_settings({'action': 'save_general', 'skin': 'default'})
                m.execute('save_general', config)
                self.assertEqual(m.settings(), saved)

    def test_skin_enum_rejects_invalid_values_and_migrates_old_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'DATA', Path(directory)):
            m.atomic_json(m.DATA / 'settings.json', {'dns_mode': 'google'})
            self.assertEqual(m.settings()['skin'], 'default')
            for value in ('custom.css', '<script>', [], None, {'theme': 'orange'}):
                with self.assertRaises(NavaError):
                    m.validate_settings({'action': 'save_general', 'skin': value})
                m.atomic_json(m.DATA / 'settings.json', {'skin': value, 'dns_mode': 'google'})
                self.assertEqual(m.settings()['skin'], 'default')
                self.assertEqual(m.settings()['dns_mode'], 'google')


if __name__ == '__main__':
    unittest.main()
