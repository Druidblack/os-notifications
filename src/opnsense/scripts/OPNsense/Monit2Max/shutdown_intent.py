#!/usr/local/bin/python3
"""Identify the shutdown operation without changing OPNsense core scripts.

OPNsense rc.reboot and rc.halt call rc.syshook stop *before* invoking
shutdown(8), so shutdown(8) audit entries do not yet exist at the early hook.
First inspect our own parent-process chain for the two official callers.
For other stop paths, fall back to fresh, timestamped shutdown(8) records.
Never infer power-off merely because a generic stop hook ran.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import re
import subprocess
import time
import os

# FreeBSD shutdown(8) writes LOG_AUTH, commonly /var/log/auth/latest.log.
# Other OPNsense syslog-ng rules may route to the following locations.
LOG_PATHS = (
    '/var/log/auth/latest.log',
    '/var/log/system/latest.log',
    '/var/log/audit/latest.log',
    '/var/log/daemon/latest.log',
    '/var/log/configd/latest.log',
    '/var/log/console/latest.log',
    '/var/log/auth.log',
    '/var/log/messages',
)

# Match only authoritative shutdown(8) process records, not incidental words
# in unrelated lines (nor Monit or plugin messages mentioning 'reboot').
DECISION = re.compile(
    r'(?i)(?:^|[\s])shutdown(?:\[\d+\])?:\s*'
    r'(?P<operation>reboot|power-down|power-cycle|halt|shutdown)\s+by\s+\S+'
)
ISO_TS = re.compile(
    r'(?<!\d)(?P<timestamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d'
    r'(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)(?!\d)'
)
BSD_TS = re.compile(r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\b')


# The OPNsense GUI executes these distinct scripts via configd.  Both call the
# same syshook BEFORE shutdown(8).  Match only the actual invoked script
# (optionally preceded by /bin/sh).  Searching arbitrary command text would be
# unsafe: a shell's "-c" argument may *mention* rc.reboot without executing it.
OFFICIAL_CALLER = re.compile(
    r'^(?:(?:/bin/sh|sh)\s+)?/usr/local/etc/rc\.(?P<action>reboot|halt)(?:\s|$)'
)


def parent_command(pid: int) -> tuple[int, str] | None:
    """Get ppid and full command line using FreeBSD's ps(1)."""
    try:
        result = subprocess.run(
            ['/bin/ps', '-ww', '-p', str(pid), '-o', 'ppid=', '-o', 'command='],
            capture_output=True, text=True, check=False, timeout=1.5,
        )
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            return None
        return int(parts[0]), parts[1]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def detect_from_process_tree(*, start_pid: int | None = None,
                             reader=None, max_depth: int = 10) -> str:
    """Return restart/shutdown/unknown from this hook's ancestry.

    The syshook script synchronously runs the Python notifier, so its ancestor
    chain normally includes /usr/local/etc/rc.reboot or rc.halt.  No system
    files are modified and no untrusted command line is included in messages.
    """
    pid = os.getppid() if start_pid is None else start_pid
    read = parent_command if reader is None else reader
    seen = set()
    for _ in range(max_depth):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        row = read(pid)
        if not row:
            break
        parent, command = row
        match = OFFICIAL_CALLER.search(command)
        if match:
            return 'restart' if match.group('action') == 'reboot' else 'shutdown'
        pid = parent
    return 'unknown'


def parse_time(line: str, now: float) -> float | None:
    """Parse the record time in local system timezone, or reject it."""
    match = ISO_TS.search(line[:80])
    if match:
        value = match.group('timestamp').replace('Z', '+00:00')
        try:
            parsed = dt.datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
            return parsed.timestamp()
        except ValueError:
            return None
    match = BSD_TS.match(line)
    if match:
        # Legacy BSD syslog lines omit the year. Handle New Year rollovers.
        try:
            local = dt.datetime.fromtimestamp(now).astimezone()
            stamp = dt.datetime.strptime(
                f"{local.year} {match.group('month')} {match.group('day')} {match.group('clock')}",
                '%Y %b %d %H:%M:%S',
            )
            stamp = stamp.replace(tzinfo=local.tzinfo)
            if stamp.timestamp() - now > 24 * 3600:
                stamp = stamp.replace(year=local.year - 1)
            return stamp.timestamp()
        except ValueError:
            return None
    return None


def classify_line(line: str, *, now: float, max_age: int = 180) -> tuple[str, float] | None:
    match = DECISION.search(line)
    if not match:
        return None
    timestamp = parse_time(line, now)
    if timestamp is None or not (-10 <= now - timestamp <= max_age):
        return None
    operation = match.group('operation').lower()
    if operation in ('reboot', 'power-cycle'):
        kind = 'restart'
    elif operation in ('halt', 'power-down'):
        kind = 'shutdown'
    else:
        # Plain shutdown(8) can enter single-user mode. Never claim poweroff.
        kind = 'unknown'
    return kind, timestamp


def detect_reason(*, paths=LOG_PATHS, now: float | None = None,
                  max_age: int = 180) -> str:
    """Return 'restart', 'shutdown' or 'unknown'. Read only recent log tails."""
    # On OPNsense 26.7 the initial stop hook precedes shutdown(8), so logs
    # cannot reliably contain the new command yet.  Process ancestry wins.
    caller_reason = detect_from_process_tree()
    if caller_reason != 'unknown':
        return caller_reason
    current = time.time() if now is None else now
    newest: tuple[float, str] | None = None
    for filename in paths:
        path = Path(filename)
        try:
            stat = path.stat()
            # Old logs cannot describe this stop event even if a line is stale.
            if current - stat.st_mtime > max_age + 10:
                continue
            with path.open('rb') as fh:
                fh.seek(max(0, stat.st_size - 65536))
                sample = fh.read(65536).decode('utf-8', 'replace')
        except OSError:
            continue
        for line in sample.splitlines():
            match = classify_line(line, now=current, max_age=max_age)
            if match and (newest is None or match[1] > newest[0]):
                newest = (match[1], match[0])
    return newest[1] if newest else 'unknown'
