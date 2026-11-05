#!/usr/local/bin/python3
"""Per-core FreeBSD CPU temperature monitoring via sysctl (stdlib only).

OPNsense reads dev.cpu.N.temperature using coretemp/amdtemp.  Do not use
hw.acpi.thermal.tzN.temperature as a fallback: these are thermal zones, not
necessarily the CPU, and can report 0.1C or other invalid values.
"""
from __future__ import annotations

import re
import subprocess
from typing import Callable

POLL_INTERVAL = 20  # seconds
CONFIRM_SAMPLES = 2
RECOVERY_MARGIN = 5  # degrees Celsius below the configured threshold
COMMAND = ['/sbin/sysctl', '-a']
SENSOR_LINE = re.compile(r'^\s*(dev\.cpu\.(\d+)\.temperature):\s*(-?\d+(?:\.\d+)?)\s*C\s*$', re.I)


def parse_sensors(output: str) -> dict[str, float]:
    """Accept only per-CPU FreeBSD temperature MIBs, ignoring ACPI zones."""
    readings = {}
    for line in output.splitlines():
        match = SENSOR_LINE.match(line)
        if not match:
            continue
        temp = float(match.group(3))
        # Ignore invalid values and internal error sentinel (-1C).
        if 1.0 <= temp <= 120.0:
            readings[match.group(1).lower()] = temp
    return readings


def read_sensors() -> dict[str, float]:
    result = subprocess.run(COMMAND, capture_output=True, text=True,
                            timeout=5, check=False, errors='replace')
    if result.returncode != 0:
        raise OSError('Unable to read FreeBSD temperature sensors')
    readings = parse_sensors(result.stdout)
    if not readings:
        raise ValueError('No CPU temperature sensors found (check Thermal Sensors driver)')
    return readings


def _sensor_key(name: str) -> int:
    return int(name.split('.')[2])


def details(readings: dict[str, float], max_sensor: str,
            max_temp: float, threshold: int, *, recovered: bool = False) -> str:
    label = 'Recovered CPU temperature' if recovered else 'High CPU temperature'
    lines = [f'{label}: {max_temp:.1f} °C',
             f'Hottest sensor: CPU {_sensor_key(max_sensor)} ({max_sensor})',
             f'Configured limit: {threshold} °C',
             f'Recovery level: {threshold - RECOVERY_MARGIN:g} °C',
             'CPU temperatures:']
    sensors = sorted(readings.items(), key=lambda item: _sensor_key(item[0]))
    lines.extend(f'CPU {_sensor_key(name)}: {value:.1f} °C' for name, value in sensors[:16])
    if len(sensors) > 16:
        lines.append(f'... and {len(sensors)-16} more sensors')
    return '\n'.join(lines)


def update(state: dict, readings: dict[str, float], threshold: int,
           now: float, on_event: Callable[[str, str, str], bool]) -> int:
    """Track confirmed high / recovered transitions, retained across restarts.

    A brief excursion across the limit cannot trigger a warning.  Once high,
    the temperature must be <= limit - 5C for two samples to recover.
    """
    if not 40 <= threshold <= 105:
        raise ValueError('Temperature threshold is outside the permitted range')
    if not readings:
        raise ValueError('No CPU sensors available')
    record = state.setdefault('cpu_temperature_state', {})
    if not isinstance(record, dict):
        record = {}
        state['cpu_temperature_state'] = record
    last_check = float(record.get('last_check', 0))
    if (last_check and now - last_check > 3 * POLL_INTERVAL) or record.get('threshold') != threshold:
        record['high_count'] = 0
        record['cool_count'] = 0
    max_sensor = max(readings, key=lambda name: readings[name])
    max_temp = readings[max_sensor]
    record.update({'last_check': now, 'threshold': threshold,
                   'highest': max_temp, 'hottest_sensor': max_sensor,
                   'readings': dict(readings), 'error': ''})
    active = bool(record.get('alert_active', False))
    if not active:
        record['cool_count'] = 0
        record['high_count'] = int(record.get('high_count', 0)) + 1 if max_temp > threshold else 0
        if record['high_count'] >= CONFIRM_SAMPLES:
            record['alert_active'] = True
            record['alarm_since'] = now
            record['high_count'] = 0
            return int(bool(on_event('CPU temperature', 'cpu_temperature_high',
                                     details(readings, max_sensor, max_temp, threshold))))
    else:
        record['high_count'] = 0
        record['cool_count'] = (int(record.get('cool_count', 0)) + 1
                                if max_temp <= threshold - RECOVERY_MARGIN else 0)
        if record['cool_count'] >= CONFIRM_SAMPLES:
            duration = max(0, int(now - float(record.get('alarm_since', now))))
            message = details(readings, max_sensor, max_temp, threshold, recovered=True)
            if duration:
                message += f'\nElevated temperature duration: {duration // 60}m {duration % 60}s'
            record['alert_active'] = False
            record['alarm_since'] = None
            record['cool_count'] = 0
            return int(bool(on_event('CPU temperature', 'cpu_temperature_recovered', message)))
    return 0
