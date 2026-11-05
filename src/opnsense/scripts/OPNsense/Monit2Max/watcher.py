#!/usr/local/bin/python3
"""OPNsense system-log event watcher and notification delivery tester (stdlib only).

Reads system/service journals without modifying monitored services or syslog.
A private test inbox validates watcher -> queue -> enabled delivery channels.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import syslog
import time
import uuid

import monit2max
import log_sources
import safe_log
import gateway_monitor
import shutdown_intent
import cpu_temperature
import health_checks

STATE_DIR = Path('/var/db/monit2max')
STATE_FILE = STATE_DIR / 'state.json'
TEST_LOG = STATE_DIR / 'delivery-test.log'
DEFAULT_LOG = '/var/log/system/latest.log'
AUTO_LOG_DIRS = ('/var/log/monit', '/var/log/system', '/var/log/daemon')
AUTO_LOG_FILES = ('/var/log/monit.log',)
PID_FILE = Path('/var/run/monit2max.pid')
MAX_QUEUE = 150
MAX_LINE = 3500
POLL_SECONDS = 4
STOP = False

# Prefix must identify the syslog program, not arbitrary messages containing Monit.
PROGRAM = re.compile(r'(?i)(?:^|[\s])monit(?:\[\d+\])?(?=[:\s])')
DIRECT_LOG = re.compile(r'^\[[0-9]{4}-[^\]]+\]\s+(?:info|warning|error|critical|debug|notice)\s*:\s*', re.I)
SERVICE = re.compile(r"['\"]([^'\"\r\n]{1,150})['\"]\s+(.+)")
RECOVERY = re.compile(r'(?i)\b(succeeded|recovered|restored|recovery|back to normal|back online)\b')
FAILURE = re.compile(r'(?i)\b(failed|failure|error|invalid|timeout|timed out|unavailable|not running|does not exist|down|refused|exceeded|stopped unexpectedly|no such|not found|matches resource limit|resource limit matched|does not match|is not accessible|connection lost)\b')
CHANGE = re.compile(r'(?i)\b(changed|change detected|modified)\b')
PROBE = re.compile(r'\bprobe_id=([0-9a-f]{32})\b')
ACTION = re.compile(r'(?i)\b(restart(?:ed|ing)?|start(?:ed|ing)?|stop(?:ped|ping)?|executed|unmonitor(?:ed|ing)?)\b')


def clean(value: str) -> str:
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', str(value)).strip()[:MAX_LINE]


def parse_monit_event(line: str, *, direct: bool = False) -> dict[str, str] | None:
    """Recognise Monit service transitions, without passing arbitrary syslog."""
    prefix = PROGRAM.search(line)
    if prefix:
        body = line[prefix.end():].lstrip(' :\t-')
    elif direct:
        match = DIRECT_LOG.match(line)
        if match is None:
            return None
        body = line[match.end():]
    else:
        return None
    service = SERVICE.search(body)
    if service is None:
        return None
    name, detail = service.groups()
    detail = clean(detail)
    if RECOVERY.search(detail):
        category = 'recovery'
    elif FAILURE.search(detail):
        category = 'failure'
    elif ACTION.search(detail):
        category = 'action'
    elif CHANGE.search(detail):
        category = 'other'
    else:
        # Not every Monit log line is an alert-worthy event.
        return None
    return {'service': clean(name), 'category': category, 'detail': detail}


def enabled(settings: dict[str, str], key: str, default: str = '1') -> bool:
    return settings.get(key, default).strip() == '1'


def accepted(settings: dict[str, str], category: str) -> bool:
    if not enabled(settings, 'enabled', '0'):
        return False
    return enabled(settings, {'failure': 'notifyfailures',
                              'recovery': 'notifyrecoveries',
                              'action': 'notifyactions'}.get(category, 'notifyother'),
                   '0' if category == 'other' else '1')


def load_state(path: Path = STATE_FILE) -> dict:
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(state, dict):
            state.setdefault('queue', [])
            state.setdefault('recent', {})
            state.setdefault('cursor', {})
            state.setdefault('cursors', {})
            return state
    except (OSError, ValueError, TypeError):
        pass
    return {'queue': [], 'recent': {}, 'cursor': {}, 'cursors': {}}


def save_state(state: dict, path: Path = STATE_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temp = path.with_suffix('.tmp.' + str(os.getpid()))
    with temp.open('w', encoding='utf-8') as fh:
        os.chmod(temp, 0o600)
        json.dump(state, fh, ensure_ascii=False, separators=(',', ':'))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, path)


def enqueue(state: dict, service: str, category: str, detail: str, now: float | None = None,
            *, channels: list[str] | None = None, cooldown: int = 90,
            original_log: str = '') -> bool:
    current = time.time() if now is None else now
    channels = list(dict.fromkeys(['max'] if channels is None else channels))
    if not channels:
        return False
    if not isinstance(state.get('queue'), list):
        state['queue'] = []
    if not isinstance(state.get('recent'), dict):
        state['recent'] = {}
    key = hashlib.sha256((service + '\0' + category + '\0' + detail).encode('utf-8')).hexdigest()
    recent = state['recent']
    if current - float(recent.get(key, -1e10)) < cooldown:
        return False
    recent[key] = current
    # Bound both memory and offline backlog.
    state['recent'] = {k: v for k, v in recent.items() if current - float(v) < 86400}
    item = {'service': service, 'category': category,
            'detail': detail, 'created': current,
            'attempts': 0, 'due': current, 'pending': channels,
            'attempts_by': {}, 'due_by': {}}
    if original_log:
        # Defense in depth: only a redacted excerpt is ever stored on disk.
        item['original_log'] = safe_log.sanitize(original_log)
    state['queue'].append(item)
    if len(state['queue']) > MAX_QUEUE:
        state['queue'] = state['queue'][-MAX_QUEUE:]
    return True


def source_paths(settings: dict[str, str]) -> list[Path]:
    """Read actual Monit and system logs: OPNsense routes syslog by program.

    Use automatic journal discovery unconditionally. Historical LogFile values
    are ignored, since this option is no longer user configurable.
    """
    paths: list[Path] = []
    for dirname in AUTO_LOG_DIRS:
        directory = Path(dirname)
        latest = directory / 'latest.log'
        if latest.is_file():
            paths.append(latest)
        elif directory.is_dir():
            # A symlink can be missing briefly after resetting OPNsense logs.
            # Choose only the newest daily file, never replay the entire archive.
            candidates = [x for x in directory.glob('*.log') if x.is_file()]
            if candidates:
                paths.append(max(candidates, key=lambda x: x.stat().st_mtime))
    for filename in AUTO_LOG_FILES:
        path = Path(filename)
        if path.is_file():
            paths.append(path)
    # Discover only enabled source-specific journals. Nothing is configured in syslog.
    for dirname in log_sources.source_directories(settings):
        directory = Path(dirname)
        latest = directory / 'latest.log'
        if latest.is_file():
            paths.append(latest)
        elif directory.is_dir():
            candidates = [x for x in directory.glob('*.log') if x.is_file()]
            # Daily archives are not replayed on startup.
            if candidates:
                paths.append(max(candidates, key=lambda x: x.stat().st_mtime))
    for filename in log_sources.extra_files(settings):
        file = Path(filename)
        if file.is_file():
            paths.append(file)
    # Suricata writes JSON rather than syslog when EVE logging is enabled.
    if log_sources.accepted(settings, 'ids'):
        for filename in ('/var/log/suricata/eve.json', '/var/log/suricata/eve.json.0'):
            file = Path(filename)
            if file.is_file():
                paths.append(file)
                break
    # A source can have different aliases/symlinks. Avoid duplicate reads.
    seen: set[tuple[int, int]] = set()
    unique: list[Path] = []
    for p in paths:
        try:
            st = p.stat()
        except OSError:
            continue
        key = (st.st_dev, st.st_ino)
        if key not in seen:
            unique.append(p)
            seen.add(key)
    return unique


def source_path(settings: dict[str, str]) -> Path:
    """Compatibility helper: first existing selected log, or default."""
    found = source_paths(settings)
    return found[0] if found else Path(DEFAULT_LOG)



def add_firewall_hit(state: dict, event: dict, now: float, *, original_log: str = '') -> None:
    """Batch packet logs; at most one aggregate alert per five minutes."""
    aggregate = state.get('firewall_aggregate')
    if not isinstance(aggregate, dict) or now - float(aggregate.get('since', 0)) >= 300:
        # Do not discard an expired bucket; the watch cycle flushes it first.
        if aggregate and now - float(aggregate.get('since', 0)) >= 300:
            state['firewall_expired'] = aggregate
        aggregate = {'since': now, 'count': 0, 'sources': {}}
        state['firewall_aggregate'] = aggregate
    aggregate['count'] += 1
    if original_log and not aggregate.get('sample_log'):
        # One representative sample, not an unbounded collection of packet logs.
        aggregate['sample_log'] = safe_log.sanitize(original_log)
    ip = event.get('source_ip', '')
    if ip:
        items = aggregate['sources']
        if ip in items or len(items) < 32:
            items[ip] = int(items.get(ip, 0)) + 1


def emit_firewall_summary(settings: dict[str, str], state: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    aggregates = []
    expired = state.pop('firewall_expired', None)
    if isinstance(expired, dict):
        aggregates.append(expired)
    aggregate = state.get('firewall_aggregate')
    if isinstance(aggregate, dict) and now - float(aggregate.get('since', 0)) >= 300:
        aggregates.append(aggregate)
        state.pop('firewall_aggregate', None)
    emitted = False
    if not log_sources.accepted(settings, 'firewall'):
        return False
    for item in aggregates:
        count = int(item.get('count', 0))
        if count < 10:
            continue
        sources = item.get('sources', {})
        popular = sorted(sources.items(), key=lambda pair: -pair[1])[:3]
        detail = f'Blocked {count} logged packets in 5 minutes.'
        if popular:
            detail += ' Top source addresses: ' + ', '.join(f'{ip} ({hits})' for ip, hits in popular)
        emitted = enqueue(state, 'Firewall', 'firewall', detail,
                          channels=monit2max.enabled_channels(settings), cooldown=60,
                          original_log=item.get('sample_log', '') if enabled(settings, 'includeoriginallog', '0') else '') or emitted
    return emitted


def new_dhcp_device(state: dict, mac: str, now: float) -> bool:
    if not mac:
        return False
    history = state.setdefault('dhcp_devices', {})
    if not isinstance(history, dict):
        history = {}
        state['dhcp_devices'] = history
    # Retain a bounded recent history, even across watcher restarts.
    if len(history) > 4000:
        history = {k: v for k, v in history.items() if now - float(v) < 30*86400}
        state['dhcp_devices'] = history
    if mac in history:
        return False
    history[mac] = now
    return True


def prepare_test_log(path: Path | None = None) -> None:
    """Create a root-only test inbox, independent of OPNsense syslog routing."""
    if path is None:
        path = TEST_LOG
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The installation already owns this directory; do not loosen its permissions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def append_test_event(path: Path, marker: str) -> None:
    """A small synthetic event; never pass credentials or user-controlled text."""
    prepare_test_log(path)
    data = ("monit[0]: 'NOTIFICATION_DELIVERY_TEST' status failed (1) -- "
            f'Notification delivery self-test probe_id={marker}\n').encode('ascii')
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def scan_log(settings: dict[str, str], state: dict, *, log: Path | None = None) -> int:
    path = log if log is not None else source_path(settings)
    try:
        stat = path.stat()
    except OSError:
        return 0
    cursors = state.setdefault('cursors', {})
    cursor_key = str(path)
    is_test_inbox = path == TEST_LOG
    cursor = cursors.get(cursor_key)
    if cursor is None and cursor_key == DEFAULT_LOG:
        # The old watcher stored only the system journal offset.
        cursor = state.get('cursor') or None
    identity = f'{stat.st_dev}:{stat.st_ino}'
    if not cursor:
        # New sources start at EOF, so reinstalling never replays old alerts.
        cursors[cursor_key] = {'id': identity, 'offset': stat.st_size}
        return 0
    offset = int(cursor.get('offset', 0))
    if cursor.get('id') != identity or stat.st_size < offset:
        offset = 0
    count = 0
    try:
        with path.open('rb') as fd:
            fd.seek(offset)
            for _ in range(2000):
                raw = fd.readline(8192)
                if not raw:
                    break
                if not raw.endswith(b'\n'):
                    fd.seek(fd.tell() - len(raw))
                    break
                line = raw.decode('utf-8', errors='replace')
                event = parse_monit_event(line, direct=(str(path) != DEFAULT_LOG))
                is_monit = event is not None
                if is_test_inbox:
                    # Only the exact internal synthetic format is accepted here.
                    if not event or event['service'] != 'NOTIFICATION_DELIVERY_TEST' or not PROBE.search(event['detail']):
                        continue
                    event['category'] = 'test'
                if not is_monit:
                    # Does not forward raw syslog lines, only explicitly recognized events.
                    event = log_sources.classify(line, path)
                if event and event['category'] in ('gateway_down', 'gateway_up', 'gateway_quality') and gateway_status_is_current(state):
                    # The OPNsense gateway status API is authoritative; suppress
                    # duplicate/out-of-order dpinger log events while it works.
                    continue
                if event:
                    if not is_test_inbox:
                        state['last_monit_event'] = time.time()
                        state['last_monit_source'] = str(path)
                    probe_match = PROBE.search(event['detail']) if is_test_inbox else None
                    permitted = (bool(monit2max.enabled_channels(settings)) if is_test_inbox
                                 else accepted(settings, event['category']) if is_monit
                                 else log_sources.accepted(settings, event['category']))
                    if probe_match:
                        probes = state.setdefault('probes', {})
                        probes[probe_match.group(1)] = {
                            'seen': time.time(), 'accepted': permitted, 'sent': False,
                            'expected': monit2max.enabled_channels(settings), 'sent_by': {},
                            'source': str(path),
                        }
                        cutoff = time.time() - 3600
                        state['probes'] = {k: v for k, v in probes.items()
                                           if float(v.get('seen', 0)) >= cutoff}
                    original_log = (safe_log.sanitize(line) if permitted and
                                    enabled(settings, 'includeoriginallog', '0') else '')
                    if permitted and event['category'] == 'firewall':
                        # An individual firewall packet must never become a message.
                        add_firewall_hit(state, event, time.time(), original_log=original_log)
                    elif permitted and event['category'] == 'dhcp_lease':
                        # A lease renewal is not a new device; track a 30-day history.
                        if new_dhcp_device(state, event.get('device', ''), time.time()):
                            if enqueue(state, event['service'], event['category'], event['detail'],
                                       channels=monit2max.enabled_channels(settings),
                                       cooldown=86400, original_log=original_log):
                                count += 1
                    elif permitted and enqueue(state, event['service'], event['category'], event['detail'],
                                               channels=monit2max.enabled_channels(settings),
                                               cooldown=(0 if is_test_inbox else 600 if event['category'] in ('gateway_down', 'gateway_quality',
                                                                                      'dns', 'backend', 'ddns_changed', 'ddns_error',
                                                                                      'vpn_down', 'crowdsec', 'crowdsec_error', 'crowdsec_decision') else 90),
                                               original_log=original_log):
                        count += 1
                    if permitted:
                        stats = state.setdefault('source_counts', {})
                        stats[event['category']] = int(stats.get(event['category'], 0)) + 1
                        state['last_source_event'] = {'source': str(path), 'category': event['category'],
                                                      'time': time.time()}
            offset = fd.tell()
    except OSError:
        return 0
    cursors[cursor_key] = {'id': identity, 'offset': offset}
    return count


def poll_gateway_status(settings: dict[str, str], state: dict,
                        now: float | None = None, *, force: bool = False) -> int:
    """Independently monitor every OPNsense gateway and enqueue transitions.

    Avoid reliance on dpinger syslog formatting, or which WAN is the default.
    A successful status query enables suppression of duplicate gateway events
    from syslog. On errors, existing gateway state is preserved.
    """
    now = time.time() if now is None else now
    if not (log_sources.accepted(settings, 'gateway_down') or
            log_sources.accepted(settings, 'gateway_quality')):
        state['gateway_monitor_active'] = False
        return 0
    last_attempt = float(state.get('gateway_last_attempt', 0))
    if not force and now - last_attempt < gateway_monitor.POLL_INTERVAL:
        return 0
    state['gateway_last_attempt'] = now
    try:
        snapshot = gateway_monitor.read_status()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        # The error text is not an arbitrary command response and contains no
        # tokens. Keep the previous state so a transient failure is not offline.
        state['gateway_poll_error'] = type(exc).__name__
        if now - float(state.get('gateway_last_check', 0)) > gateway_monitor.STALE_AFTER:
            state['gateway_monitor_active'] = False
        return 0
    channels = monit2max.enabled_channels(settings)
    def emit(name: str, category: str, detail: str) -> bool:
        if not log_sources.accepted(settings, category):
            return False
        # State transitions are deduplicated by state rather than by cooldown:
        # a fast down/up/down sequence still generates distinct alerts.
        return enqueue(state, name, category, detail, now=now,
                       channels=channels, cooldown=0)
    return gateway_monitor.update(state, snapshot, now, on_event=emit)


def poll_cpu_temperature(settings: dict[str, str], state: dict,
                         now: float | None = None, *, force: bool = False) -> int:
    """Monitor actual CPU sensors independently of system and Monit logs."""
    if not enabled(settings, 'cputempenabled', '0'):
        return 0
    now = time.time() if now is None else now
    record = state.setdefault('cpu_temperature_state', {})
    if not isinstance(record, dict):
        record = {}
        state['cpu_temperature_state'] = record
    last_attempt = float(record.get('last_attempt', 0))
    if not force and now - last_attempt < cpu_temperature.POLL_INTERVAL:
        return 0
    record['last_attempt'] = now
    try:
        threshold = int(settings.get('cputempthreshold', '75'))
        if not 40 <= threshold <= 105:
            raise ValueError('Invalid temperature threshold')
        readings = cpu_temperature.read_sensors()
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        # Never interpret missing/invalid sensors as cooling/recovery.
        record['error'] = ('No valid CPU temperature readings; check Thermal Sensors driver'
                           if not isinstance(exc, ValueError) or 'threshold' not in str(exc).lower()
                           else 'Invalid temperature threshold')
        return 0
    channels = monit2max.enabled_channels(settings)
    def emit(name: str, category: str, detail: str) -> bool:
        # The persisted high/recovery state, not a cooldown, suppresses repeats.
        return enqueue(state, name, category, detail, now=now,
                       channels=channels, cooldown=0)
    return cpu_temperature.update(state, readings, threshold, now, emit)


def gateway_status_is_current(state: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return bool(state.get('gateway_monitor_active') and
                now - float(state.get('gateway_last_check', 0)) <= gateway_monitor.STALE_AFTER)


def scan_sources(settings: dict[str, str], state: dict) -> int:
    total = sum(scan_log(settings, state, log=src) for src in source_paths(settings))
    # The test inbox is intentionally not listed as an external system journal.
    if TEST_LOG.is_file():
        total += scan_log(settings, state, log=TEST_LOG)
    return total


def cursor_ready(state: dict, src: Path) -> bool:
    try:
        st = src.stat()
    except OSError:
        return False
    cursor = state.get('cursors', {}).get(str(src), {})
    if not cursor and str(src) == DEFAULT_LOG:
        cursor = state.get('cursor', {})
    return cursor.get('id') == f'{st.st_dev}:{st.st_ino}'


def build_message(settings: dict[str, str], event: dict) -> str:
    label = {'test': 'Notification delivery test', 'failure': 'Health check problem', 'recovery': 'Health check recovered', 'action': 'Monitored service action',
             'startup': 'System startup', 'shutdown': 'System shutdown',
             'restart': 'System restart', 'stop_unknown': 'System stopping',
             'other': 'Check status changed',
             'gateway_down': 'WAN / Gateway offline', 'gateway_up': 'WAN / Gateway restored',
             'gateway_quality': 'Gateway quality', 'wan_ip': 'WAN IP changed',
             'auth': 'Administrator access', 'crowdsec': 'CrowdSec event',
             'crowdsec_error': 'CrowdSec service error',
             'crowdsec_decision': 'CrowdSec security decision',
             'vpn_down': 'VPN disconnected', 'vpn_up': 'VPN connected',
             'dns': 'DNS problem', 'dhcp': 'DHCP problem', 'dhcp_lease': 'New DHCP device',
             'ddns_changed': 'Dynamic DNS updated', 'ddns_error': 'Dynamic DNS failure',
             'firmware': 'Firmware update', 'backup': 'Backup error',
             'backend': 'Backend action failed', 'firewall': 'Firewall summary',
             'ids': 'IDS/IPS alert',
             'check_problem': 'System health warning', 'check_recovered': 'System health restored',
             'cpu_temperature_high': 'CPU temperature warning',
             'cpu_temperature_recovered': 'CPU temperature normal'}.get(event['category'], 'Event')
    created = dt.datetime.fromtimestamp(event['created']).astimezone().strftime('%Y-%m-%d %H:%M:%S %z')
    detail = event['detail']
    if enabled(settings, 'includeoriginallog', '0') and event.get('original_log'):
        # Re-sanitize legacy/untrusted queue entries when building the message.
        original = safe_log.sanitize(event['original_log'])
        if original:
            detail += '\n\nOriginal log message (redacted):\n' + original
    return monit2max.event_message(
        settings.get('title', 'OPNsense Notifications'),
        {'MONIT_HOST': socket.gethostname(), 'MONIT_SERVICE': event['service'],
         'MONIT_EVENT': label, 'MONIT_DATE': created,
         'MONIT_DESCRIPTION': detail})


def flush_queue(settings: dict[str, str], state: dict, now: float | None = None) -> int:
    """Deliver each event independently to both providers. Never replay a successful route.

    An old 0.3.2 queue item with no pending routes belongs to MAX only.
    Disabled channels are paused (not discarded) so pending events can retry.
    """
    current = time.time() if now is None else now
    count = 0
    queue = state.get('queue', [])
    selected = set(monit2max.enabled_channels(settings))
    for event in list(queue)[:10]:
        if current - float(event['created']) > 24 * 3600:
            queue.remove(event)
            continue
        pending = event.setdefault('pending', ['max'])
        attempts_by = event.setdefault('attempts_by', {})
        due_by = event.setdefault('due_by', {})
        # v0.3.2 retry state remains meaningful for its legacy MAX task.
        if 'max' in pending and 'max' not in due_by and 'due' in event:
            due_by['max'] = float(event['due'])
            attempts_by['max'] = int(event.get('attempts', 0))
        for channel in list(pending):
            if channel not in selected or float(due_by.get(channel, 0)) > current:
                continue
            try:
                monit2max.deliver(settings, channel, build_message(settings, event))
                pending.remove(channel)
                attempts_by.pop(channel, None)
                due_by.pop(channel, None)
                probe_match = PROBE.search(event.get('detail', ''))
                if probe_match:
                    record = state.setdefault('probes', {}).get(probe_match.group(1))
                    if record is not None:
                        record.setdefault('sent_by', {})[channel] = time.time()
                        expected = record.get('expected', ['max'])
                        if all(record['sent_by'].get(key) for key in expected):
                            record['sent'] = time.time()
                state['last_sent'] = current
                state.setdefault('last_sent_by', {})[channel] = current
                state.setdefault('last_error_by', {}).pop(channel, None)
                count += 1
            except monit2max.NotifyError as exc:
                error = str(exc)
                state['last_error'] = f'{channel}: {error}'
                state.setdefault('last_error_by', {})[channel] = error
                attempt = int(attempts_by.get(channel, 0)) + 1
                attempts_by[channel] = attempt
                due_by[channel] = current + min(1800, 15 * 2 ** min(attempt, 7))
                if channel == 'max':
                    event['due'] = due_by[channel]
                    event['attempts'] = attempt
                if attempt in (1, 5):
                    syslog.syslog(syslog.LOG_WARNING, f'monit2max: pending {channel} notification: {error}')
            except Exception:
                state['last_error'] = f'{channel}: unexpected delivery error'
                state.setdefault('last_error_by', {})[channel] = 'Unexpected delivery error'
                attempt = int(attempts_by.get(channel, 0)) + 1
                attempts_by[channel] = attempt
                due_by[channel] = current + 120
                if channel == 'max':
                    event['due'] = due_by[channel]
                    event['attempts'] = attempt
                syslog.syslog(syslog.LOG_ERR, f'monit2max: {channel} queued-delivery failure')
        if not pending:
            queue.remove(event)
    if not state.get('last_error_by'):
        state.pop('last_error', None)
    return count


def watch(config: Path = monit2max.DEFAULT_CONFIG, path: Path = STATE_FILE, pause: float = POLL_SECONDS, once: bool = False) -> None:
    global STOP
    prepare_test_log()
    state = load_state(path)
    def stop(_signum, _frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not STOP:
        try:
            settings = monit2max.read_settings(config)
            if enabled(settings, 'enabled', '0'):
                poll_gateway_status(settings, state)
                poll_cpu_temperature(settings, state)
                health_checks.poll(settings, state, lambda service, category, detail: enqueue(
                    state, service, category, detail, channels=monit2max.enabled_channels(settings), cooldown=0))
                scan_sources(settings, state)
                emit_firewall_summary(settings, state)
                state['last_scan'] = time.time()
                save_state(state, path)
                flush_queue(settings, state)
            save_state(state, path)
        except Exception:
            state['last_error'] = 'Watcher cycle failed: check log file and configuration'
            try:
                save_state(state, path)
            except OSError:
                pass
            syslog.syslog(syslog.LOG_ERR, 'monit2max: watch cycle failed (check config and log source)')
        if once:
            break
        time.sleep(pause)


def current_boot_identity() -> str:
    """Stable OPNsense boot identifier (kern.boottime) for stop deduplication."""
    try:
        result = subprocess.run(['/sbin/sysctl', '-n', 'kern.boottime'],
                                capture_output=True, text=True, timeout=2,
                                check=False)
        if result.returncode == 0:
            return result.stdout.strip()[:150]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ''


def lifecycle(kind: str, config: Path = monit2max.DEFAULT_CONFIG, path: Path = STATE_FILE) -> dict:
    settings = monit2max.read_settings(config)
    if not enabled(settings, 'enabled', '0'):
        return {'status': 'ok', 'message': 'Notifications disabled'}
    if kind == 'startup':
        if not enabled(settings, 'notifystartup'):
            return {'status': 'ok', 'message': 'Startup notifications disabled'}
        channels = monit2max.enabled_channels(settings)
        if not channels:
            return {'status': 'ok', 'message': 'No messenger enabled'}
        state = load_state(path)
        bootid = os.popen('/sbin/sysctl -n kern.boottime 2>/dev/null').read().strip() or str(int(time.time()))
        if state.get('last_boot') != bootid:
            enqueue(state, 'OPNsense', 'startup', 'System boot completed; network startup hook executed.', channels=channels)
            state['last_boot'] = bootid
            save_state(state, path)
        return {'status': 'ok', 'message': 'Startup notification queued'}
    if kind == 'shutdown':
        if not enabled(settings, 'notifyshutdown'):
            return {'status': 'ok', 'message': 'Shutdown notifications disabled'}
        channels = monit2max.enabled_channels(settings)
        if not channels:
            return {'status': 'ok', 'message': 'No messenger enabled'}
        # OPNsense can invoke the same "stop" hook twice: once from rc.reboot/
        # rc.halt (while networking works) and later from rc.shutdown.  Keep a
        # separate per-boot delivery marker to avoid duplicate notifications,
        # without racing the main watcher's persistent queue state.
        marker_path = path.with_name('stop-notification.json')
        boot_identity = current_boot_identity()
        current = time.time()
        try:
            marker = json.loads(marker_path.read_text(encoding='utf-8'))
            if not isinstance(marker, dict):
                marker = {}
        except (OSError, ValueError, TypeError):
            marker = {}
        same_boot = (bool(boot_identity) and marker.get('boot') == boot_identity)
        if not boot_identity:
            # Only for environments without a readable kern.boottime.
            # The normal OPNsense case always uses the exact boot identity.
            same_boot = (marker.get('boot') == '' and
                         0 <= current - float(marker.get('created', 0)) < 120)
        if not same_boot:
            marker = {'boot': boot_identity, 'created': current,
                      'reason': shutdown_intent.detect_reason(), 'sent': []}
            save_state(marker, marker_path)
        elif marker.get('reason') not in ('restart', 'shutdown') and not marker.get('sent'):
            # First attempt failed before delivery; a later stop hook may have
            # a more conclusive reason, such as a shutdown(8) log entry.
            marker['reason'] = shutdown_intent.detect_reason()
            save_state(marker, marker_path)
        reason = marker.get('reason', 'unknown')
        event_info = {
            'restart': ('restart', 'OPNsense is restarting normally.'),
            'shutdown': ('shutdown', 'OPNsense is shutting down normally.'),
            'unknown': ('stop_unknown',
                        'OPNsense is stopping normally. Could not determine whether this is a restart or a power-off.'),
        }
        category, detail = event_info.get(reason, event_info['unknown'])
        event = {'service': 'OPNsense', 'category': category, 'created': current,
                 'detail': detail}
        already_sent = set(marker.get('sent', []))
        failed = []
        for channel in channels:
            if channel in already_sent:
                continue
            try:
                monit2max.deliver(settings, channel, build_message(settings, event),
                                  timeout=5, rate_limit=False)
                already_sent.add(channel)
                marker['sent'] = sorted(already_sent)
                # Save after each successful channel to survive an interrupted
                # shutdown and avoid redelivery in a later stop hook.
                save_state(marker, marker_path)
            except Exception:
                failed.append(channel)
        if failed:
            return {'status': 'failed', 'message': 'System stop notification failed for ' + ', '.join(failed)}
        return {'status': 'ok', 'message': 'System stop notification delivered (or previously sent) to ' + ', '.join(channels)}
    raise ValueError('unknown lifecycle event')


def status(config: Path = monit2max.DEFAULT_CONFIG, path: Path = STATE_FILE) -> dict:
    settings = monit2max.read_settings(config)
    state = load_state(path)
    # The shutdown handler writes a separate marker so status can show the
    # previous reboot/power-off decision even after the system starts again.
    try:
        last_stop = json.loads(path.with_name('stop-notification.json').read_text(encoding='utf-8'))
        if not isinstance(last_stop, dict):
            last_stop = {}
    except (OSError, ValueError, TypeError):
        last_stop = {}
    sources = source_paths(settings)
    try:
        pid = int(PID_FILE.read_text(encoding='ascii').strip())
        os.kill(pid, 0)
        running = True
    except (OSError, ValueError):
        running = False
    return {'status': 'ok', 'enabled': enabled(settings, 'enabled', '0'),
            'watcher_running': running,
            'log_file': ', '.join(str(src) for src in sources) or '(none)',
            'log_sources': [str(src) for src in sources],
            'log_available': bool(sources),
            'queued': len(state.get('queue', [])),
            'channels': monit2max.enabled_channels(settings),
            'last_sent_by': state.get('last_sent_by', {}),
            'last_error_by': state.get('last_error_by', {}),
            'cursor_initialized': bool(sources) and any(cursor_ready(state, src) for src in sources),
            'delivery_test_ready': cursor_ready(state, TEST_LOG),
            'last_monit_event': state.get('last_monit_event'),
            'last_monit_source': state.get('last_monit_source'),
            'health_checks': state.get('health_checks', {}),
            'cpu_temperature': dict(state.get('cpu_temperature_state', {}),
                                    enabled=enabled(settings, 'cputempenabled', '0')),
            'gateway_poll_active': gateway_status_is_current(state),
            'gateway_poll_error': state.get('gateway_poll_error', ''),
            'gateway_last_check': state.get('gateway_last_check'),
            'gateway_states': {name: {key: row.get(key) for key in ('condition', 'address', 'monitor', 'delay', 'loss', 'since')}
                               for name, row in state.get('gateway_states', {}).items()
                               if isinstance(row, dict)},
            'last_scan': state.get('last_scan'),
            'last_sent': state.get('last_sent'),
            'last_error': state.get('last_error', ''),
            'last_stop_reason': last_stop.get('reason'),
            'last_stop_time': last_stop.get('created'),
            'last_stop_sent_to': last_stop.get('sent', []),
            'additional_sources': [str(src) for src in sources
                                   if log_sources.hint_for(src) not in ('system', 'monit')],
            'source_counts': state.get('source_counts', {}),
            'last_source_event': state.get('last_source_event', {})}


def marker_in_log(logfile: Path, marker: str) -> bool:
    """Check the tail; avoid reading large log archives."""
    try:
        with logfile.open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 256 * 1024))
            return marker.encode('ascii') in stream.read()
    except OSError:
        return False


def pipeline_test(config: Path = monit2max.DEFAULT_CONFIG, path: Path = STATE_FILE,
                  *, wait_seconds: float = 16) -> dict[str, str]:
    """Check test inbox -> watcher -> queue -> provider delivery, without syslog."""
    settings = monit2max.read_settings(config)
    if not enabled(settings, 'enabled', '0'):
        return {'status': 'failed', 'message': 'Enable notifications and save settings first.'}
    channels = monit2max.enabled_channels(settings)
    if not channels:
        return {'status': 'failed', 'message': 'Enable at least one destination (MAX, Telegram or Gotify).'}
    try:
        prepare_test_log()
    except OSError:
        return {'status': 'failed', 'message': 'Cannot create the private notification test inbox.'}
    for _ in range(15):
        state = load_state(path)
        if cursor_ready(state, TEST_LOG):
            break
        time.sleep(.3)
    else:
        return {'status': 'failed', 'message':
                'Notification watcher has not initialized the delivery test inbox. '
                'Apply settings, then check monitoring status.'}
    marker = uuid.uuid4().hex
    try:
        append_test_event(TEST_LOG, marker)
    except OSError:
        return {'status': 'failed', 'message': 'Cannot write the private notification test event.'}
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        record = load_state(path).get('probes', {}).get(marker)
        if record:
            if record.get('sent'):
                return {'status': 'ok', 'message':
                        'Verified: test event was processed by the notification watcher '
                        'and delivered to ' + ', '.join(channels) + '. '
                        'This does not test routing of actual system logs.'}
            if not record.get('accepted'):
                return {'status': 'failed', 'message':
                        'The watcher saw the test but could not queue it for any enabled destination.'}
        time.sleep(.4)
    state = load_state(path)
    record = state.get('probes', {}).get(marker)
    if record:
        errors = state.get('last_error_by', {})
        pending = [x for x in record.get('expected', channels) if x not in record.get('sent_by', {})]
        details = '; '.join(f'{ch}: {errors[ch]}' for ch in pending if ch in errors)
        return {'status': 'failed', 'message':
                'Test event was processed, but not all destinations confirmed delivery. '
                'Waiting for: ' + ', '.join(pending) +
                ('. Last delivery errors: ' + details if details else '')}
    if marker_in_log(TEST_LOG, marker):
        return {'status': 'failed', 'message':
                'Test event was written to the private test inbox, but the notification '
                'watcher did not process it. Check monitoring status.'}
    return {'status': 'failed', 'message':
            'Test event was not found in the private test inbox. Check file permissions.'}

def main() -> int:
    p = argparse.ArgumentParser(description='OPNsense notification log watcher')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--watch', action='store_true')
    group.add_argument('--once', action='store_true')
    group.add_argument('--status', action='store_true')
    group.add_argument('--startup', action='store_true')
    group.add_argument('--shutdown', action='store_true')
    group.add_argument('--pipeline-test', action='store_true')
    args = p.parse_args()
    try:
        if args.watch or args.once:
            watch(once=args.once)
            return 0
        if args.pipeline_test:
            result = pipeline_test()
        elif args.status:
            result = status()
        else:
            result = lifecycle('startup' if args.startup else 'shutdown')
        print(json.dumps(result))
        return 0 if result.get('status') == 'ok' else 1
    except monit2max.NotifyError as error:
        print(json.dumps({'status': 'failed', 'message': str(error)}))
        return 1
    except Exception:
        syslog.syslog(syslog.LOG_ERR, 'monit2max: watcher operation failed')
        print(json.dumps({'status': 'failed', 'message': 'Watcher error; check System logs'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
