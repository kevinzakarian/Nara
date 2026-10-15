import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, build_config, parse_subscription


class BulkUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.nodes, _ = parse_subscription('trojan://secret@203.0.113.8:443')
        handle = patch.object(m, 'DATA', self.data)
        handle.start(); self.addCleanup(handle.stop)

    def test_bulk_update_keeps_active_preferences_and_reports_partial_failure(self):
        urls = ['https://one.test/sub', 'http://two.test/sub', 'https://three.test/sub']
        entries = [{'id': m._subscription_id(url), 'name': 'Provider %d' % i, 'url': url} for i, url in enumerate(urls)]
        config = {**m.DEFAULTS, 'subscriptions': entries, 'active_subscription': entries[0]['id'], 'subscription_url': urls[0], 'dns_mode': 'custom', 'custom_dns': '9.9.9.9'}
        m.atomic_json(self.data / 'settings.json', config)
        old = {'nodes': self.nodes, 'updated': 111, 'source_hash': hashlib.sha256(urls[1].encode()).hexdigest()}
        m.save_cache({**config, 'active_subscription': entries[1]['id'], 'subscription_url': urls[1]}, old)
        def fetch(target):
            if target['subscription_url'] == urls[1]:
                raise NavaError('Download failed')
            return {'nodes': self.nodes, 'updated': 222, 'source_hash': hashlib.sha256(target['subscription_url'].encode()).hexdigest()}
        with patch.object(m, 'fetch_subscription', side_effect=fetch), patch.object(m, 'job_update'), patch.object(m, 'activate', return_value=False) as activate:
            with self.assertRaisesRegex(NavaError, '2 of 3 subscriptions updated'):
                m.execute('update_all_subscriptions', config)
            activate.assert_not_called()
        self.assertEqual(m.read_json(self.data / 'settings.json'), config)
        cache = m.read_json(self.data / 'subscription.json')['entries']
        self.assertEqual(cache[entries[1]['id']]['updated'], 111)
        self.assertEqual(cache[entries[0]['id']]['updated'], 222)
        self.assertEqual(cache[entries[2]['id']]['updated'], 222)


if __name__ == '__main__':
    unittest.main()
