import io
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import NavaError, parse_subscription


def elf(machine, bits=2, little=True):
    data = bytearray(64)
    data[:6] = b'\x7fELF' + bytes([bits, 1 if little else 2])
    data[18:20] = struct.pack('<H' if little else '>H', machine)
    return data


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.patches = [patch.object(m, 'DATA', self.base / 'data'), patch.object(m, 'RUN', self.base / 'run'), patch.object(m, 'CORE', self.base / 'core/sing-box')]
        for item in self.patches:
            item.start()
        m.DATA.mkdir(); m.RUN.mkdir(); m.CORE.parent.mkdir()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.temp.cleanup()

    def test_architectures(self):
        for machine, bits, little, expected in [(62, 2, True, 'amd64'), (3, 1, True, '386'), (183, 2, True, 'arm64'), (8, 1, False, 'mips-softfloat'), (8, 1, True, 'mipsle-softfloat'), (8, 2, False, 'mips64-softfloat'), (8, 2, True, 'mips64le-softfloat'), (243, 2, True, 'riscv64'), (258, 2, True, 'loong64')]:
            with self.subTest(expected=expected):
                self.assertEqual(m.architecture(elf(machine, bits, little)), expected)

    def test_only_running_core_counts_as_a_connected_tunnel(self):
        for core_running in (False, True):
            instances = {'core': {'running': core_running}, 'dns': {'running': True}, 'worker': {'running': True}}
            result = type('Result', (), {'stdout': json.dumps({'nava': {'instances': instances}})})()
            with self.subTest(core_running=core_running), patch.object(m, 'command', return_value=result):
                self.assertEqual(m.running(), core_running)
        with patch.object(m, 'command', return_value=type('Result', (), {'stdout': '{"nava":{"instances":{"dns":{"running":true}}}}'})()):
            self.assertFalse(m.running())

    def test_arm_variants(self):
        for level in [5, 6, 7, 8]:
            self.assertEqual(m.architecture(elf(40, 1), 'CPU architecture : %d' % level), 'armv%d' % min(level, 7))

    def test_unknown_architecture_fails(self):
        with self.assertRaises(NavaError):
            m.architecture(elf(999))

    def test_url_validation(self):
        m.validate_url('https://example.com/sub?token=ABC%2F123')
        m.validate_url('http://example.com/subscription')
        for url in ['file:///etc/shadow', 'https://user:pass@example.com', 'https://example.com\noutput=/etc/shadow', 'https://example.com/#foo', 'https://example.com:99999']:
            with self.subTest(url=url), self.assertRaises(NavaError):
                m.validate_url(url)

    def test_private_file_permissions(self):
        path = m.DATA / 'settings.json'
        m.atomic_json(path, {'subscription_url': 'secret'})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(m.read_json(path)['subscription_url'], 'secret')

    def test_blank_url_keeps_existing(self):
        m.atomic_json(m.DATA / 'settings.json', {**m.DEFAULTS, 'subscription_url': 'https://example.com/token'})
        self.assertEqual(m.validate_settings({'subscription_url': ''})['subscription_url'], 'https://example.com/token')

    def test_settings_migrates_original_http_link(self):
        m.atomic_json(m.DATA / 'settings.json', {**m.DEFAULTS, 'subscription_url': 'http://example.com/token'})
        config = m.settings()
        self.assertEqual(len(config['subscriptions']), 1)
        self.assertEqual(config['subscriptions'][0]['url'], 'http://example.com/token')
        self.assertEqual(config['active_subscription'], config['subscriptions'][0]['id'])

    def test_multiple_subscription_add_select_rename_and_delete(self):
        first = m.validate_settings({'action': 'connect', 'subscription_url': 'https://one.example/sub',
                                     'subscription_name': 'Work', 'selected': 'auto', 'ipv6': True,
                                     'autostart': False, 'dns_mode': 'default', 'custom_dns': ''})
        m.atomic_json(m.DATA / 'settings.json', first)
        second = m.validate_settings({'action': 'connect', 'subscription_url': 'http://two.example/sub', 'subscription_id': '',
                                      'subscription_name': 'Home', 'selected': 'auto', 'ipv6': True,
                                      'autostart': False, 'dns_mode': 'google', 'custom_dns': ''})
        self.assertEqual(len(second['subscriptions']), 2)
        self.assertEqual(second['subscriptions'][-1]['name'], 'Home')
        m.atomic_json(m.DATA / 'settings.json', second)
        preserved = m.validate_settings({'action': 'update', 'subscription_id': '', 'selected': 'auto',
                                         'ipv6': True, 'autostart': False, 'dns_mode': 'google', 'custom_dns': ''})
        self.assertEqual(preserved['active_subscription'], second['active_subscription'])
        first_id = first['subscriptions'][0]['id']
        selected = m.validate_settings({'action': 'select_subscription', 'subscription_id': first_id,
                                        'subscription_name': 'Renamed work', 'selected': 'auto', 'ipv6': True,
                                        'autostart': False, 'dns_mode': 'default', 'custom_dns': ''})
        self.assertEqual(selected['active_subscription'], first_id)
        self.assertEqual(selected['subscriptions'][0]['name'], 'Renamed work')
        m.atomic_json(m.DATA / 'settings.json', selected)
        deleted = m.validate_settings({'action': 'delete_subscription', 'subscription_id': first_id,
                                       'selected': 'auto', 'ipv6': True, 'autostart': False,
                                       'dns_mode': 'default', 'custom_dns': ''})
        self.assertEqual(len(deleted['subscriptions']), 1)
        self.assertEqual(deleted['subscriptions'][0]['name'], 'Home')

    def test_invalid_selection_and_boolean(self):
        for params in [{'selected': ';touch /tmp/test'}, {'ipv6': 'false'}, {'subscription_url': []}]:
            with self.assertRaises(NavaError):
                m.validate_settings(params)

    def add_saved_subscription(self, url, name):
        config = m.validate_settings({'action': 'add_subscription', 'subscription_url': url, 'subscription_name': name})
        sid = config['operation_subscription']
        nodes, _ = parse_subscription('trojan://secret@example.test:443#Initial')
        cache = {'nodes': nodes, 'updated': 100, 'source_hash': hashlib.sha256(url.encode()).hexdigest()}
        with patch.object(m, 'fetch_subscription', return_value=cache):
            m.execute('add_subscription', config)
        return sid

    def test_new_subscriptions_stay_inactive_across_reload(self):
        with patch.object(m, 'service') as service:
            self.add_saved_subscription('http://one.example/sub', 'One')
            self.add_saved_subscription('https://two.example/sub', 'Two')
        saved = m.settings()
        self.assertEqual(len(saved['subscriptions']), 2)
        self.assertEqual(saved['active_subscription'], '')
        self.assertEqual(saved['subscription_url'], '')
        self.assertNotIn('operation_subscription', m.read_json(m.DATA / 'settings.json'))
        service.assert_not_called()

    def test_edit_keeps_active_subscription_and_invalidates_only_changed_url(self):
        first = self.add_saved_subscription('https://one.example/sub', 'One')
        second = self.add_saved_subscription('http://two.example/sub', 'Two')
        saved = m.settings()
        saved.update(active_subscription=first, subscription_url=saved['subscriptions'][0]['url'], dns_mode='google', autostart=True)
        m.atomic_json(m.DATA / 'settings.json', saved)
        m.atomic_json(m.DATA / 'subscription.json', {'entries': {first: {'nodes': []}, second: {'nodes': []}}})
        rename = m.validate_settings({'action': 'edit_subscription', 'subscription_id': second, 'subscription_name': 'Renamed', 'subscription_url': ''})
        m.execute('edit_subscription', rename)
        self.assertIn(second, m.read_json(m.DATA / 'subscription.json')['entries'])
        config = m.validate_settings({'action': 'edit_subscription', 'subscription_id': second,
                                      'subscription_name': 'Home', 'subscription_url': 'https://new.example/token', 'dns_mode': 'cloudflare', 'autostart': False})
        with patch.object(m, 'service') as service:
            m.execute('edit_subscription', config)
        saved = m.settings()
        self.assertEqual(saved['active_subscription'], first)
        self.assertEqual(saved['subscriptions'][1]['name'], 'Home')
        self.assertEqual(saved['subscriptions'][1]['url'], 'https://new.example/token')
        self.assertEqual(saved['dns_mode'], 'google')
        self.assertTrue(saved['autostart'])
        self.assertEqual(set(m.read_json(m.DATA / 'subscription.json')['entries']), {first})
        service.assert_not_called()

    def test_update_other_subscription_preserves_connection_and_migrates_cache(self):
        first = self.add_saved_subscription('https://one.example/sub', 'One')
        second = self.add_saved_subscription('http://two.example/sub', 'Two')
        saved = m.settings()
        saved.update(active_subscription=first, subscription_url=saved['subscriptions'][0]['url'])
        m.atomic_json(m.DATA / 'settings.json', saved)
        nodes, _ = parse_subscription('trojan://SECRET@node.example:443#One')
        old_cache = {'nodes': nodes, 'source_hash': hashlib.sha256(saved['subscription_url'].encode()).hexdigest()}
        m.atomic_json(m.DATA / 'subscription.json', old_cache)
        before = (m.DATA / 'settings.json').read_bytes()
        config = m.validate_settings({'action': 'update_subscription', 'subscription_id': second})
        new_cache = {'nodes': nodes, 'updated': 123, 'source_hash': hashlib.sha256(b'http://two.example/sub').hexdigest()}
        with patch.object(m, 'fetch_subscription', return_value=new_cache) as fetch, patch.object(m, 'service') as service:
            m.execute('update_subscription', config)
        self.assertEqual(fetch.call_args.args[0]['subscription_url'], 'http://two.example/sub')
        self.assertEqual((m.DATA / 'settings.json').read_bytes(), before)
        self.assertEqual(m.settings()['active_subscription'], first)
        self.assertEqual(set(m.read_json(m.DATA / 'subscription.json')['entries']), {first, second})
        with patch.object(m, 'running', return_value=True):
            status = m.status()
        self.assertEqual(status['subscriptions'][1]['nodes'][0]['name'], 'One')
        self.assertEqual(status['subscriptions'][1]['updated'], 123)
        self.assertNotIn('SECRET', json.dumps(status))
        service.assert_not_called()

    def test_delete_does_not_select_another_subscription(self):
        first = self.add_saved_subscription('https://one.example/sub', 'One')
        second = self.add_saved_subscription('http://two.example/sub', 'Two')
        third = self.add_saved_subscription('https://three.example/sub', 'Three')
        saved = m.settings()
        saved.update(active_subscription=first, subscription_url=saved['subscriptions'][0]['url'])
        m.atomic_json(m.DATA / 'settings.json', saved)
        m.execute('delete_subscription', m.validate_settings({'action': 'delete_subscription', 'subscription_id': second}))
        self.assertEqual(m.settings()['active_subscription'], first)
        m.execute('delete_subscription', m.validate_settings({'action': 'delete_subscription', 'subscription_id': first}))
        self.assertEqual(m.settings()['active_subscription'], '')
        self.assertEqual(m.settings()['subscriptions'][0]['id'], third)

    def test_readding_original_url_after_edit_uses_distinct_id(self):
        first = self.add_saved_subscription('https://one.example/sub', 'One')
        m.execute('edit_subscription', m.validate_settings({'action': 'edit_subscription', 'subscription_id': first,
                  'subscription_url': 'https://two.example/sub', 'subscription_name': 'Two'}))
        second = self.add_saved_subscription('https://one.example/sub', 'One again')
        self.assertNotEqual(first, second)
        self.assertEqual(len(m.settings()['subscriptions']), 2)

    def test_connection_choice_is_not_saved_before_activation(self):
        first = self.add_saved_subscription('https://one.example/sub', 'One')
        second = self.add_saved_subscription('http://two.example/sub', 'Two')
        saved = m.settings()
        saved.update(active_subscription=first, subscription_url=saved['subscriptions'][0]['url'])
        m.atomic_json(m.DATA / 'settings.json', saved)
        chosen = m.validate_settings({'action': 'connect', 'subscription_id': second})
        self.assertEqual(chosen['active_subscription'], second)
        self.assertEqual(m.settings()['active_subscription'], first)

    def test_worker_accepts_settings_with_many_saved_links(self):
        config = {**m.DEFAULTS, 'subscriptions': [{'url': 'https://example.com/' + 'a' * 3000} for _ in range(8)]}
        payload = json.dumps(config).encode()
        self.assertGreater(len(payload), 16384)
        with io.TextIOWrapper(io.BytesIO(payload)) as stdin, patch.object(m.sys, 'stdin', stdin), patch.object(m, 'execute', return_value='Saved.') as execute:
            descriptor = os.open(os.devnull, os.O_RDONLY)
            m.worker('add_subscription', descriptor)
        execute.assert_called_once_with('add_subscription', config)
        self.assertEqual(m.read_json(m.RUN / 'job.json')['state'], 'done')

    def release(self):
        name = 'sing-box-1.14.3-linux-amd64.tar.gz'
        return {'tag_name': 'v1.14.3', 'assets': [{'name': name, 'size': 1024, 'digest': 'sha256:' + 'a' * 64,
                'browser_download_url': 'https://github.com/SagerNet/sing-box/releases/download/v1.14.3/' + name}]}

    def test_stable_release_selection(self):
        version, asset = m.choose_asset(self.release(), 'amd64')
        self.assertEqual(version, '1.14.3')
        self.assertTrue(asset['name'].endswith('-amd64.tar.gz'))

    def test_openwrt_prefers_musl_release_asset(self):
        release = self.release()
        musl_name = 'sing-box-1.14.3-linux-amd64-musl.tar.gz'
        release['assets'].insert(0, {'name': musl_name, 'size': 2048, 'digest': 'sha256:' + 'b' * 64,
            'browser_download_url': 'https://github.com/SagerNet/sing-box/releases/download/v1.14.3/' + musl_name})
        _, asset = m.choose_asset(release, 'amd64')
        self.assertEqual(asset['name'], musl_name)

    def test_reject_untrusted_release_metadata(self):
        for kind in ['prerelease', 'digest', 'url', 'architecture', 'version']:
            release = self.release()
            arch = 'amd64'
            if kind == 'prerelease': release['prerelease'] = True
            if kind == 'digest': release['assets'][0]['digest'] = None
            if kind == 'url': release['assets'][0]['browser_download_url'] = 'https://evil.example/core'
            if kind == 'architecture': arch = 'unsupported'
            if kind == 'version': release['tag_name'] = 'v1.14.4-beta.1'
            with self.subTest(kind=kind), self.assertRaises(NavaError):
                m.choose_asset(release, arch)

    def tar(self, name='sing-box-test/sing-box', kind=tarfile.REGTYPE):
        path = self.base / 'archive.tar.gz'
        with tarfile.open(path, 'w:gz') as t:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 4 if kind == tarfile.REGTYPE else 0
            member.linkname = '/etc/shadow' if kind == tarfile.SYMTYPE else ''
            t.addfile(member, io.BytesIO(b'core') if member.size else None)
        return path

    def test_safe_binary_extraction(self):
        output = m.CORE.with_suffix('.new')
        m.extract_core(self.tar(), output)
        self.assertEqual(output.read_bytes(), b'core')
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_tar_traversal_and_symlink_rejected(self):
        for name, kind in [('../sing-box', tarfile.REGTYPE), ('/etc/sing-box', tarfile.REGTYPE), ('sing-box/sing-box', tarfile.SYMTYPE)]:
            with self.subTest(name=name), self.assertRaises(NavaError):
                m.extract_core(self.tar(name, kind), m.CORE)

    def test_status_does_not_expose_secrets(self):
        m.atomic_json(m.DATA / 'settings.json', {**m.DEFAULTS, 'subscription_url': 'https://example.com/SUPERSECRET'})
        nodes, _ = parse_subscription('trojan://PASSWORD@example.com:443#Node')
        m.atomic_json(m.DATA / 'subscription.json', {'nodes': nodes})
        with patch.object(m, 'running', return_value=False):
            output = json.dumps(m.status())
        self.assertNotIn('SUPERSECRET', output)
        self.assertNotIn('PASSWORD', output)

    def test_interrupted_job_reported(self):
        m.atomic_json(m.RUN / 'job.json', {'state': 'running', 'message': 'Old'})
        with patch.object(m, 'running', return_value=False):
            self.assertEqual(m.status()['job']['state'], 'error')

    def test_invalid_config_does_not_stop_service(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        m.atomic_json(m.DATA / 'config.json', {'old': True})
        with patch.object(m, 'running', return_value=True), patch.object(m, 'check_config', side_effect=NavaError('Invalid')), patch.object(m, 'service') as service:
            with self.assertRaises(NavaError):
                m.activate(m.DEFAULTS, {'nodes': nodes})
            service.assert_not_called()
        self.assertEqual(m.read_json(m.DATA / 'config.json'), {'old': True})

    def test_start_failure_restores_previous_config_and_service(self):
        nodes, _ = parse_subscription('trojan://secret@example.com:443')
        m.atomic_json(m.DATA / 'config.json', {'old': True})
        with patch.object(m, 'running', return_value=True), patch.object(m, 'check_config'), patch.object(m, 'wait_running', side_effect=NavaError('Failed')), patch.object(m, 'service') as service:
            with self.assertRaises(NavaError):
                m.activate(m.DEFAULTS, {'nodes': nodes})
            self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop', 'start'])
        self.assertEqual(m.read_json(m.DATA / 'config.json'), {'old': True})
        self.assertFalse((m.DATA / 'settings.json').exists())

    def test_disconnect_disables_autostart(self):
        with patch.object(m, 'service') as service:
            m.execute('disconnect', m.DEFAULTS)
        self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'disable'])
        self.assertFalse(m.settings()['autostart'])

    def test_download_hides_url_and_checks_tls(self):
        url = 'https://example.com/TOPSECRET'
        path = self.base / 'sub'
        def run(args, **kwargs):
            self.assertNotIn(url, args)
            self.assertIn('TOPSECRET', kwargs['input'])
            self.assertNotIn('--insecure', args)
            self.assertIn('--proto-redir', args)
            path.write_text('test')
            return type('Result', (), {'returncode': 0})()
        with patch.object(m, 'command', side_effect=run):
            m.download(url, path)

    def fake_release_download(self, corrupt=False):
        archive = self.tar().read_bytes()
        release = self.release()
        release['assets'][0]['size'] = len(archive)
        release['assets'][0]['digest'] = 'sha256:' + ('0' * 64 if corrupt else hashlib.sha256(archive).hexdigest())
        def download(url, destination, **kwargs):
            destination.write_bytes(json.dumps(release).encode() if url == m.RELEASE_API else archive)
        return download

    def test_checksum_mismatch_keeps_old_core(self):
        m.CORE.write_bytes(b'old')
        with patch.object(m, 'download', side_effect=self.fake_release_download(corrupt=True)), patch.object(m, 'architecture', return_value='amd64'), patch.object(m, 'core_version', return_value='1.14.2'), patch.object(m, 'service') as service:
            with self.assertRaisesRegex(NavaError, 'checksum'):
                m.update_core()
            service.assert_not_called()
        self.assertEqual(m.CORE.read_bytes(), b'old')

    def test_core_update_start_failure_rolls_back_binary(self):
        m.CORE.write_bytes(b'old')
        def version(binary=None):
            return '1.14.3' if binary is not None else '1.14.2'
        with patch.object(m, 'download', side_effect=self.fake_release_download()), patch.object(m, 'architecture', return_value='amd64'), patch.object(m, 'core_version', side_effect=version), patch.object(m, 'running', return_value=True), patch.object(m, 'wait_running', side_effect=NavaError('Failed')), patch.object(m, 'service') as service:
            with self.assertRaises(NavaError):
                m.update_core()
            self.assertEqual([x.args[0] for x in service.call_args_list], ['stop', 'start', 'stop', 'start'])
        self.assertEqual(m.CORE.read_bytes(), b'old')
        self.assertFalse(m.CORE.with_name('sing-box.new').exists())

    def test_successful_core_update_retains_backup(self):
        m.CORE.write_bytes(b'old')
        with patch.object(m, 'download', side_effect=self.fake_release_download()), patch.object(m, 'architecture', return_value='amd64'), patch.object(m, 'core_version', side_effect=['1.14.2', '1.14.3']), patch.object(m, 'running', return_value=False):
            self.assertEqual(m.update_core(), '1.14.3')
        self.assertEqual(m.CORE.read_bytes(), b'core')
        self.assertEqual(m.CORE.with_name('sing-box.previous').read_bytes(), b'old')
        self.assertEqual(m.read_json(m.DATA / 'core.json')['version'], '1.14.3')

    def test_simultaneous_operation_refused(self):
        import fcntl
        with (m.RUN / 'operation.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(m.busy())
            with self.assertRaisesRegex(NavaError, 'progress'):
                m.enqueue({'action': 'update'})
        self.assertFalse(m.busy())


if __name__ == '__main__':
    unittest.main()
