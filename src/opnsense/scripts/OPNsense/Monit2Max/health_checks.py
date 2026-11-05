#!/usr/local/bin/python3
"""Read-only OPNsense health checks. No write access to monitored services.

All checks are opt-in, bounded, and hold their state across watcher restarts.
A missing measurement is *unknown*, never an implicit recovery.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

POLL = {'storage': 900, 'resources': 60,
        'aliases': 900, 'certificates': 3600, 'backups': 3600}
SYSTEM_CONFIG = Path('/conf/config.xml')
ALIASES = Path('/var/db/aliastables')


def command(argv: list[str], *, input_data: str | None = None, timeout: int = 8) -> str:
    done = subprocess.run(argv, input=input_data, text=True, capture_output=True,
                          timeout=timeout, check=False)
    if done.returncode:
        raise OSError(f'{Path(argv[0]).name} exited with code {done.returncode}')
    return done.stdout[:256_000]


def percent(settings: dict, key: str, default: int) -> int:
    value = int(settings.get(key, str(default)))
    if not 1 <= value <= 100:
        raise ValueError('percentage must be from 1 to 100')
    return value


def integer(settings: dict, key: str, default: int, low: int, high: int) -> int:
    value = int(settings.get(key, str(default)))
    if not low <= value <= high:
        raise ValueError('configured limit out of range')
    return value


def enabled(settings: dict, key: str) -> bool:
    return settings.get(key, '0').strip() == '1'


def state_transition(state: dict, key: str, bad: bool, service: str, description: str,
                     recovery: str, emit, *, confirm: int = 2) -> int:
    """Debounce both edges. Do not flood or announce recovery on missing inputs."""
    row = state.setdefault('items', {}).setdefault(key, {})
    prior = bool(row.get('bad', False))
    if bad == prior:
        row['pending'] = 0
        row['candidate'] = bad
        return 0
    if row.get('candidate') != bad:
        row['candidate'] = bad
        row['pending'] = 0
    row['pending'] = int(row.get('pending', 0)) + 1
    if row['pending'] < confirm:
        return 0
    row['bad'] = bad
    row['pending'] = 0
    row['since'] = time.time()
    return int(bool(emit(service, 'check_problem' if bad else 'check_recovered',
                         description if bad else recovery)))


def smart_measurements(settings: dict) -> list[tuple[str, bool, str]]:
    """smartctl JSON provides reliable status for SATA, NVMe and USB devices."""
    utility = next((str(p) for p in (Path('/usr/local/sbin/smartctl'), Path('/usr/sbin/smartctl'))
                    if p.is_file()), None)
    if not utility:
        raise OSError('smartctl unavailable; install/enable smartmontools (os-smart)')
    scanned = json.loads(command([utility, '--scan-open', '-j']))
    devices = scanned.get('devices', [])
    if not isinstance(devices, list):
        raise ValueError('SMART device list is invalid')
    result = []
    wear = percent(settings, 'smartwearlimit', 90)
    heat = integer(settings, 'smarttemplimit', 65, 40, 100)
    for item in devices[:12]:
        name = str(item.get('name', ''))
        if not re.fullmatch(r'/dev/[A-Za-z0-9_./-]{1,100}', name) or '..' in name:
            continue
        dtype = str(item.get('type', ''))
        argv = [utility, '-a', '-j', name]
        if re.fullmatch(r'[A-Za-z0-9_,-]{1,24}', dtype):
            argv += ['-d', dtype]
        try:
            # smartctl uses nonzero bit flags for warnings. Parse valid JSON even then.
            output = subprocess.run(argv, capture_output=True, text=True, timeout=4, check=False)
            details = json.loads(output.stdout)
            if not isinstance(details, dict):
                raise ValueError('SMART response is not an object')
            if not (details.get('smart_status') or details.get('nvme_smart_health_information_log')
                    or details.get('temperature')):
                raise ValueError('SMART attributes not available')
            health = details.get('smart_status', {})
            nvme = details.get('nvme_smart_health_information_log', {})
            temp = details.get('temperature', {}).get('current')
            if temp is None:
                temp = nvme.get('temperature')
            worn = nvme.get('percentage_used')
            reasons = []
            if health.get('passed') is False:
                reasons.append('SMART health check failed')
            warning = nvme.get('critical_warning', 0)
            try:
                if int(warning):
                    reasons.append(f'NVMe critical warning: {int(warning)}')
            except (TypeError, ValueError):
                pass
            if isinstance(worn, (int, float)) and worn >= wear:
                reasons.append(f'NVMe lifetime used: {worn}% (limit {wear}%)')
            if isinstance(temp, (int, float)) and temp >= heat:
                reasons.append(f'Drive temperature: {temp} °C (limit {heat} °C)')
            diag = f'{name}: ' + ('; '.join(reasons) if reasons else 'SMART healthy')
            result.append((name, bool(reasons), diag))
        except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
            # Individual inaccessible disks do not suppress valid disks.
            continue
    if not result:
        raise ValueError('No readable SMART data for detected drives')
    return result


def resource_measurements(settings: dict) -> list[tuple[str, bool, str]]:
    result = []
    swap = command(['/usr/sbin/swapinfo', '-k'], timeout=4)
    lines = [x.split() for x in swap.splitlines()[1:]]
    # FreeBSD columns: Device 1K-blocks Used Avail Capacity, terminal total row.
    totals = [r for r in lines if len(r) >= 4 and r[0].lower() == 'total']
    if totals:
        row = totals[-1]
        total, used = int(row[1]), int(row[2])
    else:
        valid = [r for r in lines if len(r) >= 4 and r[1].isdigit() and r[2].isdigit()]
        total, used = sum(int(r[1]) for r in valid), sum(int(r[2]) for r in valid)
    if total > 0:
        load = round(100 * used / total, 1)
        limit = percent(settings, 'swaplimit', 80)
        result.append(('swap', load >= limit, f'Swap: {load}% used (limit {limit}%)'))
    # PF current state count and configured hard limit; never modify PF.
    try:
        states = command(['/sbin/pfctl', '-si'], timeout=5)
        limits = command(['/sbin/pfctl', '-sm'], timeout=5)
        active = re.search(r'(?im)^\s*current entries\s+(\d+)', states)
        hard = re.search(r'(?im)^\s*states\s+hard limit\s+(\d+)', limits)
        if active and hard and int(hard[1]) > 0:
            usage = round(100 * int(active[1]) / int(hard[1]), 1)
            limit = percent(settings, 'pflimit', 80)
            result.append(('pf', usage >= limit,
                           f'Firewall state table: {int(active[1])}/{int(hard[1])} ({usage}%, limit {limit}%)'))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    # FreeBSD netstat -m (the current/total/max numbers are version-dependent).
    try:
        output = command(['/usr/bin/netstat', '-m'], timeout=4)
        clusters = re.search(r'(?im)^\s*(\d+)/(\d+)/(\d+)/(\d+)\s+mbuf clusters in use', output)
        if clusters and int(clusters[4]) > 0:
            usage = round(100 * (int(clusters[1]) + int(clusters[2])) / int(clusters[4]), 1)
            limit = percent(settings, 'mbuflimit', 80)
            result.append(('mbuf', usage >= limit,
                           f'Mbuf clusters allocated: {usage}% of limit (warning {limit}%)'))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    if not result:
        raise ValueError('No measurable swap, firewall state or mbuf limits')
    return result


def read_config(path: Path = SYSTEM_CONFIG) -> ET.Element:
    # No DTD / external entities; do not log or transmit config contents.
    return ET.parse(path).getroot()


def alias_measurements(settings: dict, config: Path = SYSTEM_CONFIG,
                       alias_dir: Path = ALIASES, now: float | None = None) -> list[tuple[str, bool, str]]:
    now = time.time() if now is None else now
    root = read_config(config)
    maxage = integer(settings, 'aliasagehours', 48, 1, 720) * 3600
    results = []
    for alias in root.findall('./OPNsense/Firewall/Alias/aliases/alias'):
        if (alias.findtext('enabled') or '1') == '0':
            continue
        if (alias.findtext('type') or '') not in ('urltable', 'urltable_json'):
            continue
        name = alias.findtext('name') or ''
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name):
            continue
        file = alias_dir / (name + '.txt')
        try:
            stat = file.stat()
            age = max(0, now - stat.st_mtime)
            # A zero-byte URL table is an error even if freshly updated.
            bad = age > maxage or stat.st_size == 0
            reason = ('empty downloaded list' if stat.st_size == 0 else
                      f'last saved {age / 3600:.1f} hours ago; limit {maxage / 3600:.0f} hours')
            results.append((name, bad, f'Firewall Alias {name}: {reason}'))
        except OSError:
            results.append((name, True, f'Firewall Alias {name}: downloaded list not found in {alias_dir}'))
    return results


def certificate_measurements(settings: dict, config: Path = SYSTEM_CONFIG,
                             now: float | None = None) -> list[tuple[str, bool, str, int]]:
    """Check configured web GUI leaf cert; optionally all local non-CA leaf certs."""
    now = time.time() if now is None else now
    root = read_config(config)
    webref = root.findtext('./system/webgui/ssl-certref') or ''
    all_leaf = enabled(settings, 'certall')
    results = []
    for cert in root.findall('./cert'):
        ref = cert.findtext('refid') or ''
        if not all_leaf and ref != webref:
            continue
        if not all_leaf and not webref:
            continue
        data = cert.findtext('crt') or ''
        if not data or len(data) > 200_000:
            continue
        try:
            pem = base64.b64decode(data, validate=True).decode('ascii')
            if '-----BEGIN CERTIFICATE-----' not in pem:
                continue
            raw = command(['/usr/bin/openssl', 'x509', '-noout', '-enddate'],
                          input_data=pem, timeout=4)
            match = re.search(r'notAfter=(.+)', raw)
            if not match:
                continue
            expiry = dt.datetime.strptime(' '.join(match[1].split()), '%b %d %H:%M:%S %Y %Z')
            remaining = (expiry.replace(tzinfo=dt.timezone.utc).timestamp() - now) / 86400
            name = re.sub(r'[^A-Za-z0-9 ._@-]', '', cert.findtext('descr') or 'certificate')[:80]
            warn_days = 30 if remaining <= 30 else 0
            if remaining <= 7:
                warn_days = 7
            if remaining <= 1:
                warn_days = 1
            if remaining < 0:
                warn_days = -1
            desc = f'Certificate {name}: expires {expiry.strftime("%Y-%m-%d")} UTC, {remaining:.1f} days remaining'
            results.append((ref or name, remaining <= 30, desc, warn_days))
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
            continue
    if not results:
        raise ValueError('No readable configured certificate')
    return results


def backup_measurements(settings: dict, now: float | None = None) -> list[tuple[str, bool, str]]:
    """Check freshness of LOCAL snapshots only; does NOT prove remote delivery."""
    now = time.time() if now is None else now
    path = Path(settings.get('backupdirectory', '/conf/backup').strip())
    if not path.is_absolute() or '..' in path.parts or len(str(path)) > 220:
        raise ValueError('Backup folder must be an absolute path without traversal')
    if not path.is_dir():
        raise ValueError('Local backup folder is not available')
    ages = []
    for item in list(path.iterdir())[:2048]:
        if item.is_symlink() or not item.is_file():
            continue
        if item.name.lower().endswith(('.xml', '.xml.gz', '.xml.ydenc', '.json.gz', '.backup', '.bak')):
            ages.append(item.stat().st_mtime)
    if not ages:
        raise ValueError('No local backup snapshot files found (XML, .bak or .backup)')
    age_days = round(max(0, now - max(ages)) / 86400, 1)
    limit = integer(settings, 'backupagedays', 2, 1, 365)
    return [('Local configuration backup', age_days >= limit,
             f'Latest local backup snapshot: {age_days} days old (limit {limit} days); folder: {path}. '
             'This check does not verify uploads to Git or cloud storage.')]


def cert_transitions(state: dict, values: list[tuple[str, bool, str, int]], emit) -> int:
    count = 0
    for name, bad, detail, level in values:
        row = state.setdefault('items', {}).setdefault('cert:' + name, {})
        old = int(row.get('level', 0))
        if level == old:
            continue
        row['level'] = level
        if level and (old == 0 or level != old):
            count += int(bool(emit('Certificate ' + name, 'check_problem', detail)))
        elif old:
            count += int(bool(emit('Certificate ' + name, 'check_recovered', detail)))
    return count


def poll(settings: dict, state: dict, emit, *, now: float | None = None,
         force: bool = False, config: Path = SYSTEM_CONFIG,
         alias_dir: Path = ALIASES) -> int:
    """Poll opt-in checks on independent schedules; never stop other checks on failure."""
    now = time.time() if now is None else now
    groups = state.setdefault('health_checks', {})
    if not isinstance(groups, dict):
        groups = {}
        state['health_checks'] = groups
    # Discard obsolete v0.6.8 DNS-probe status and Git backup health history.
    # Existing log-based DNS and Git backup error notifications remain intact.
    groups.pop('dns_probe', None)
    backup_history = groups.get('backups', {}).get('items', {})
    if isinstance(backup_history, dict):
        backup_history.pop('Local Git backup history', None)
    checks = (
        ('storage', 'smartenabled', lambda: smart_measurements(settings)),
        ('resources', 'resourcesenabled', lambda: resource_measurements(settings)),
        ('aliases', 'aliasenabled', lambda: alias_measurements(settings, config, alias_dir, now)),
        ('certificates', 'certenabled', lambda: certificate_measurements(settings, config, now)),
        ('backups', 'backupfreshnessenabled', lambda: backup_measurements(settings, now)),
    )
    count = 0
    for group, setting, reader in checks:
        row = groups.setdefault(group, {})
        row['enabled'] = enabled(settings, setting)
        if not row['enabled']:
            continue
        if not force and now - float(row.get('last_check', 0)) < POLL[group]:
            continue
        row['last_check'] = now
        try:
            results = reader()
            row.pop('error', None)
            row['sources'] = len(results)
            row['last_success'] = now
            if group == 'certificates':
                count += cert_transitions(row, results, emit)
            else:
                for key, bad, detail in results:
                    name = {'storage': 'Disk ' + key, 'resources': 'System resource ' + key,
                            'aliases': 'Firewall Alias ' + key,
                            'backups': key}[group]
                    count += state_transition(row, key, bad, name, detail,
                                              name + ': normal again. ' + detail,
                                              emit, confirm=2)
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, ET.ParseError) as exc:
            # Do not send attacker-controlled stderr/credentials from commands.
            row['error'] = {
                'storage': 'SMART data unavailable; check smartmontools, enabled SMART support and disk access',
                'resources': 'Cannot read swap, PF or mbuf statistics',
                'aliases': 'Unable to inspect URL Table aliases and cached downloads',
                'certificates': 'Unable to read web GUI certificate or inspect its expiry with OpenSSL',
                'backups': 'Local backup folder unavailable or contains no snapshots',
            }[group]
    return count
