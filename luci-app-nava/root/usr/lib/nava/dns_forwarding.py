"""Temporary dnsmasq forwarding, owned by the Nava service, never UCI edits."""
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

from subscription import NavaError

RUN = Path('/var/run/nava')
CONFIG_DIR = Path('/var/etc')
MARKER = '# Managed by Nava; removed on disconnect.\n'
CONTENT = MARKER + 'no-resolv\nserver=/#/127.0.0.1#15353\n'
def directories():
    """OpenWrt 24.10 uses a different conf-dir for each dnsmasq instance."""
    result = set()
    for config in CONFIG_DIR.glob('dnsmasq.conf*'):
        for line in config.read_text().splitlines():
            line = line.strip().removeprefix('--')
            if line.startswith('conf-dir='):
                directory = line.split('=', 1)[1].split(',', 1)[0].strip().strip('"\'')
                if directory.startswith('/'):
                    result.add(Path(directory))
    if not result:
        raise NavaError('Cannot locate the active dnsmasq configuration. DNS override was not applied.')
    return result


def restart():
    result = subprocess.run(['/etc/init.d/dnsmasq', 'restart'], capture_output=True, timeout=25)
    if result.returncode:
        raise NavaError('dnsmasq could not restart. The DNS override was rolled back.')


def status(state, message='', generation=None):
    from manager import atomic_json, read_json
    with (RUN / 'dns.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if generation is None or read_json(RUN / 'dns-generation.json') == generation:
            atomic_json(RUN / 'dns-status.json', {'state': state, 'message': message})


def arm():
    from manager import atomic_json
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    generation = uuid.uuid4().hex
    with (RUN / 'dns.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        atomic_json(RUN / 'dns-generation.json', generation)
        atomic_json(RUN / 'dns-status.json', {'state': 'starting'})
    return generation


def current(generation):
    from manager import read_json
    return read_json(RUN / 'dns-generation.json') == generation


def update(enabled, generation=None):
    from manager import atomic_json, read_json
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (RUN / 'dns.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if generation is not None and not current(generation):
            return False
        previous = read_json(RUN / 'dns-files.json', [])
        owned = {Path(path) for path in previous if isinstance(path, str) and Path(path).name == 'nava.conf'}
        if not enabled:
            # A crash between writing a file and saving the manifest must not
            # leave router DNS pointed at a stopped listener indefinitely.
            try:
                candidates = {directory / 'nava.conf' for directory in directories()}
            except NavaError:
                candidates = set()
            owned |= candidates
        desired = {directory / 'nava.conf' for directory in directories()} if enabled else set()
        changed, originals = False, {}
        try:
            for path in owned | desired:
                if path.is_symlink():
                    raise NavaError('The dnsmasq Nava forwarding file is a symlink. DNS override was not applied.')
                old = path.read_text() if path.exists() else None
                if old is not None and not old.startswith(MARKER):
                    if path in desired:
                        raise NavaError('A different nava.conf already exists in dnsmasq. DNS override was not applied.')
                    continue
                originals[path] = old
                wanted = CONTENT if path in desired else None
                if old == wanted:
                    continue
                changed = True
                if wanted is None:
                    path.unlink(missing_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(wanted)
                    # dnsmasq drops privileges before reading its conf-dir.
                    path.chmod(0o644)
            if changed:
                restart()
            atomic_json(RUN / 'dns-files.json', sorted(map(str, desired)))
            return True
        except Exception:
            if not enabled:
                # Never put a dead DNS listener back during stop/Default.
                # Keep the manifest for a retry if filesystem removal failed.
                try:
                    removed = all(not path.exists() or not path.read_text().startswith(MARKER) for path in owned)
                except OSError:
                    removed = False
                if changed and removed:
                    try:
                        restart()
                        atomic_json(RUN / 'dns-files.json', [])
                        return True
                    except Exception:
                        pass
                raise NavaError('DNS forwarding files were removed where possible, but dnsmasq could not reload. Retry disconnect.') from None
            for path, old in originals.items():
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(old)
                    path.chmod(0o644)
            if changed:
                try:
                    restart()
                except Exception:
                    pass
            raise


def needed():
    from manager import read_json
    config = read_json(Path('/etc/nava/config.json'), {})
    return any(item.get('tag') == 'nava-dns-in' for item in config.get('inbounds', []))


def available():
    try:
        with socket.create_connection(('127.0.0.1', 15353), timeout=1):
            return True
    except OSError:
        return False


def watch(generation):
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    status('starting', generation=generation)
    try:
        for _ in range(30):
            if stopping or not current(generation):
                return
            if available():
                break
            time.sleep(1)
        else:
            raise NavaError('The DNS listener did not start. DNS override was not applied.')
        if not update(True, generation):
            return
        status('ready', generation=generation)
        while not stopping and current(generation):
            time.sleep(3)
            # If the core stops unexpectedly, restore upstream DNS. Once
            # procd respawns it, forwarding is installed again.
            online = available()
            if not update(online, generation):
                break
            status('ready' if online else 'starting', generation=generation)
    except Exception as exc:
        status('error', str(exc) if isinstance(exc, NavaError) else 'DNS forwarding failed. Check dnsmasq and retry.', generation)
    finally:
        update(False, generation)


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['needed']:
        sys.exit(0 if needed() else 1)
    elif sys.argv[1:] == ['reset']:
        arm()  # Invalidate the old watcher before removing forwarding.
        try:
            update(False)
            status('off')
        except NavaError as exc:
            status('error', str(exc))
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    elif sys.argv[1:] == ['arm']:
        print(arm())
    elif len(sys.argv) == 3 and sys.argv[1] == 'watch':
        watch(sys.argv[2])
