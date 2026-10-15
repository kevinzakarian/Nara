import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('build', BASE / 'scripts/build.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.path = module.build()

    def test_unpack_into_empty_root_with_opkg_directory_semantics(self):
        # opkg opens regular files directly; it does not create their parent
        # directories unless told to do so. tarfile.extractall() hides this bug
        # because it creates missing parents automatically.
        with tempfile.TemporaryDirectory() as directory, tarfile.open(self.path, 'r:gz') as outer:
            root = Path(directory)
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./data.tar.gz').read()), mode='r:gz') as data:
                for member in data:
                    destination = root / member.name
                    self.assertTrue(destination.parent.is_dir(), 'Missing parent directory before unpacking ' + member.name)
                    if member.isdir():
                        destination.mkdir(exist_ok=True)
                    else:
                        self.assertTrue(member.isfile(), 'Unexpected archive member type')
                        with data.extractfile(member) as source, destination.open('wb') as target:
                            shutil.copyfileobj(source, target)
                    destination.chmod(member.mode)
            for name in ['etc/nava/settings.json', 'usr/lib/nava/manager.py', 'usr/lib/nava/subscription.py',
                         'usr/lib/nava/dns_forwarding.py', 'usr/lib/nava/network_cleanup.py', 'usr/lib/nava/diagnostics.py', 'usr/libexec/rpcd/nava', 'www/luci-static/resources/nava/nava.css']:
                self.assertTrue((root / name).is_file(), name)
            self.assertEqual((root / 'etc/nava').stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'usr/libexec/rpcd/nava').stat().st_mode & 0o777, 0o755)

    def test_parent_directories_present_in_all_package_archives(self):
        with tarfile.open(self.path, 'r:gz') as outer:
            for layer in ['./control.tar.gz', './data.tar.gz']:
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read()), mode='r:gz') as archive:
                    created = {Path('.')}
                    for member in archive:
                        path = Path(member.name)
                        self.assertIn(path.parent, created, member.name)
                        if member.isdir():
                            created.add(path)

    def test_openwrt_container_and_permissions(self):
        with tarfile.open(self.path, 'r:gz') as outer:
            self.assertEqual(outer.extractfile('./debian-binary').read(), b'2.0\n')
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./data.tar.gz').read()), mode='r:gz') as data:
                members = {item.name: item for item in data}
                for name in ['etc/init.d/nava', 'usr/libexec/rpcd/nava', 'etc/uci-defaults/90-nava']:
                    self.assertEqual(members['./' + name].mode, 0o755)
                self.assertEqual(members['./etc/nava/settings.json'].mode, 0o600)
                self.assertIn('./www/luci-static/resources/view/nava.js', members)
                self.assertIn('./usr/share/rpcd/acl.d/luci-app-nava.json', members)
                self.assertTrue(all(m.uid == m.gid == 0 for m in members.values()))
                self.assertFalse(any('__pycache__' in name or name.endswith('.pyc') for name in members))
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./control.tar.gz').read()), mode='r:gz') as control:
                metadata = control.extractfile('./control').read().decode()
                self.assertIn('Architecture: all', metadata)
                for dependency in ['python3', 'kmod-tun', 'kmod-nft-queue', 'firewall4', 'luci-base', 'conntrack']:
                    self.assertIn(dependency, metadata)
                self.assertEqual(control.extractfile('./conffiles').read(), b'/etc/nava/settings.json\n')

    def test_upgrade_invalidates_same_size_python_bytecode_and_preserves_settings(self):
        with tempfile.TemporaryDirectory() as directory, tarfile.open(self.path, 'r:gz') as outer:
            root = Path(directory)
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./data.tar.gz').read()), mode='r:gz') as data:
                data.extractall(root, filter='data')
            library = root / 'usr/lib/nava'
            manager = library / 'manager.py'
            current = manager.read_text()
            # Only the version changes: identical length and archive mtime.
            old = current.replace('APP_VERSION = "1.0.0-', 'APP_VERSION = "9.9.9-')
            self.assertEqual(len(old), len(current))
            manager.write_text(old)
            import os
            os.utime(manager, (0, 0))
            command = [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import manager; print(manager.APP_VERSION)', str(library)]
            old_version = subprocess.check_output(command, text=True).strip()
            manager.write_text(current)
            os.utime(manager, (0, 0))
            self.assertEqual(subprocess.check_output(command, text=True).strip(), old_version, 'The test must reproduce stale same-size bytecode.')
            settings = root / 'etc/nava/settings.json'
            settings.write_text('{"subscription_url":"https://example.test/private","dns_mode":"custom"}')
            # Reinstalling the restored feature must retain generated lists.
            routing_file = library / 'routing.py'
            routing_before = routing_file.read_bytes()
            generated = root / 'etc/nava/routing-lists/generation-existing/ir-ip.srs'
            generated.parent.mkdir(parents=True)
            generated.write_bytes(b'existing routing list')
            before = settings.read_bytes()
            # Execute the actual first-install/upgrade script against a mapped
            # temporary filesystem, never the host's /etc or /usr/lib.
            script = (root / 'etc/uci-defaults/90-nava').read_text()
            script = script.replace('/etc/nava', '"' + str(root / 'etc/nava') + '"').replace('/usr/lib/nava', '"' + str(library) + '"')
            subprocess.run(['sh', '-c', script], check=True, capture_output=True)
            self.assertEqual(settings.read_bytes(), before)
            self.assertEqual(routing_file.read_bytes(), routing_before)
            self.assertEqual(generated.read_bytes(), b'existing routing list')
            self.assertFalse((library / '__pycache__').exists())
            self.assertNotEqual(subprocess.check_output(command, text=True).strip(), old_version)


if __name__ == '__main__':
    unittest.main()
