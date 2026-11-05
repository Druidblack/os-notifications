#!/usr/local/bin/python3
"""OPNsense 26.7 gateway status poller for independent multi-WAN notifications.

Read OPNsense's native gateway_status.php JSON, never probe arbitrary targets or
change routing. Only confirmed transitions are emitted. This module does not
send messages and is testable with recorded status snapshots.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

GATEWAY_STATUS_COMMAND = '/usr/local/opnsense/scripts/routes/gateway_status.php'
POLL_INTERVAL = 12
STALE_AFTER = 45
MAX_OUTPUT_BYTES = 1024 * 1024
# We accept only the normal OPNsense status tokens.
STATUS_MAP = {
    'none': 'online',
    'delay': 'degraded',
    'loss': 'degraded',
    'delay+loss': 'degraded',
    'down': 'offline',
    'force_down': 'offline',
}
SAFE_GATEWAY = re.compile(r'^[a-zA-Z0-9_.:-]{1,90}$')
SAFE_METRIC = re.compile(r'^[~0-9. %a-zA-Z-]{1,35}$')
SAFE_IP = re.compile(r'^[0-9a-zA-Z.:_%~-]{1,100}$')


def read_status(command: str = GATEWAY_STATUS_COMMAND, *, timeout: float = 7.0) -> dict:
    """Fetch canonical per-gateway state from OPNsense 26.7 (no shell)."""
    result = subprocess.run([command], check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise RuntimeError('OPNsense gateway status query returned an error')
    if len(result.stdout) > MAX_OUTPUT_BYTES:
        raise ValueError('OPNsense gateway status response was too large')
    raw = json.loads(result.stdout.decode('utf-8'))
    if not isinstance(raw, dict):
        raise ValueError('Unexpected OPNsense gateway status format')
    return raw


def valid_gateway(name: str, item: object) -> dict | None:
    if not isinstance(name, str) or not SAFE_GATEWAY.fullmatch(name):
        return None
    if not isinstance(item, dict):
        return None
    raw_status = str(item.get('status', '')).strip().lower()
    condition = STATUS_MAP.get(raw_status)
    if condition is None:
        return None
    # Missing monitoring metrics with normal status generally means monitor
    # disabled. Do not report a healthy gateway solely from this default.
    if raw_status == 'none' and str(item.get('loss', '~')).strip() == '~':
        return None
    values = {}
    for label in ('address', 'monitor', 'delay', 'loss', 'stddev'):
        value = str(item.get(label, '~')).strip()
        regex = SAFE_METRIC if label in ('delay', 'loss', 'stddev') else SAFE_IP
        values[label] = value if regex.fullmatch(value) else '~'
    values.update({'name': name, 'condition': condition, 'raw_status': raw_status})
    return values


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f'{days}d')
    if hours:
        parts.append(f'{hours}h')
    if minutes:
        parts.append(f'{minutes}m')
    if not parts or sec:
        parts.append(f'{sec}s')
    return ' '.join(parts)


def details(gw: dict) -> str:
    lines = [f'Gateway: {gw["name"]}']
    if gw['address'] != '~':
        lines.append(f'Gateway address: {gw["address"]}')
    if gw['monitor'] != '~':
        lines.append(f'Monitor target: {gw["monitor"]}')
    if gw['delay'] != '~':
        lines.append(f'Latency: {gw["delay"]}')
    if gw['loss'] != '~':
        lines.append(f'Packet loss: {gw["loss"]}')
    return '\n'.join(lines)


def update(state: dict, raw_status: dict, now: float, *, on_event,
           confirm: int = 2) -> int:
    """Maintain gateway-specific states, emit only confirmed transitions.

    `on_event(gateway_name, category, detail)` returns True if queued.
    An initial online gateway is baselined quietly; an initially down gateway
    is reported after two consistent samples. Existing states survive daemon
    restarts and carry the offline start time for recovery duration.
    """
    saved = state.setdefault('gateway_states', {})
    count = 0
    for name, raw in raw_status.items():
        gw = valid_gateway(name, raw)
        if gw is None:
            continue
        current = gw['condition']
        record = saved.get(name)
        if not isinstance(record, dict):
            # Initial online status is not itself a change; persistent initial
            # offline/degraded should still trigger an alert after confirmation.
            record = {'condition': 'online', 'since': now,
                      'pending': None, 'pending_count': 0, 'seen': now}
            saved[name] = record
        previous = record.get('condition', 'online')
        record['seen'] = now
        record['address'] = gw['address']
        record['monitor'] = gw['monitor']
        record['delay'] = gw['delay']
        record['loss'] = gw['loss']
        record['raw_status'] = gw['raw_status']
        if current == previous:
            record['pending'] = None
            record['pending_count'] = 0
            continue
        if record.get('pending') != current:
            record['pending'] = current
            record['pending_count'] = 1
        else:
            record['pending_count'] = int(record.get('pending_count', 0)) + 1
        if record['pending_count'] < confirm:
            continue
        record['pending'] = None
        record['pending_count'] = 0
        offline_since = float(record.get('since', now))
        record['condition'] = current
        record['since'] = now
        info = details(gw)
        category = None
        if current == 'offline':
            category = 'gateway_down'
            text = 'This gateway is offline according to OPNsense monitoring.\n' + info
            if gw['raw_status'] == 'force_down':
                text += '\nStatus: administratively forced offline'
        elif previous == 'offline':
            category = 'gateway_up'
            text = ('This gateway is reachable again.\n' + info +
                    '\nOffline duration: ' + duration(now - offline_since))
            if current == 'degraded':
                text += '\nThe connection still has excessive latency or packet loss.'
        elif current == 'degraded':
            category = 'gateway_quality'
            text = 'Gateway performance has degraded.\n' + info
        elif previous == 'degraded':
            category = 'gateway_quality'
            text = 'Gateway latency and packet loss returned to normal.\n' + info
        if category and on_event(name, category, text):
            count += 1
    # A removed or unmonitored gateway is not a connectivity failure.
    # Drop stale state only when the gateway no longer appears at all in the
    # authoritative response; never generate a fake offline event.
    for name in list(saved):
        if name not in raw_status or (isinstance(raw_status[name], dict) and
                                      raw_status[name].get('status') == 'none' and
                                      str(raw_status[name].get('loss', '~')).strip() == '~'):
            saved.pop(name, None)
    state['gateway_last_check'] = now
    state['gateway_monitor_active'] = any(valid_gateway(name, item) is not None
                                          for name, item in raw_status.items())
    state.pop('gateway_poll_error', None)
    return count
