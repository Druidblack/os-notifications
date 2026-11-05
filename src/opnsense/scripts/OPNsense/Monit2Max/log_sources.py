#!/usr/local/bin/python3
"""Conservative OPNsense log classifiers (no third party dependencies).

Only known programs or file locations are considered, and sent details are
constructed from fixed phrases plus validated IP/hostname fields. Never relay
raw audit, auth, URL or provider response bodies: they can contain credentials.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re

# Values in settings.conf are lowercase because ConfigParser normalises keys.
FILTERS = {
    'gateway_down': ('notifygatewaystatus', '1'),
    'gateway_up': ('notifygatewaystatus', '1'),
    'gateway_quality': ('notifygatewayquality', '1'),
    'wan_ip': ('notifywanip', '0'),
    'auth': ('notifyauth', '1'),
    'crowdsec': ('notifycrowdsec', '1'),  # Pending events created by v0.5.0
    'crowdsec_error': ('notifycrowdsec', '1'),
    'crowdsec_decision': ('notifycrowdsec', '1'),
    'vpn_down': ('notifyvpn', '1'),
    'vpn_up': ('notifyvpn', '1'),
    'dns': ('notifydns', '1'),
    'dhcp': ('notifydhcp', '1'),
    'dhcp_lease': ('notifydhcpleases', '0'),
    'ddns_changed': ('notifyddnschanges', '1'),
    'ddns_error': ('notifyddnserrors', '1'),
    'firmware': ('notifyfirmware', '1'),
    'backup': ('notifybackup', '1'),
    'backend': ('notifybackend', '1'),
    'firewall': ('notifyfirewall', '0'),
    'ids': ('notifyids', '0'),
}

SOURCE_DIRS = {
    'gateway': ('/var/log/gateways', '/var/log/gateway'),
    'auth': ('/var/log/audit', '/var/log/lighttpd'),
    'crowdsec': ('/var/log/crowdsec',),
    'vpn': ('/var/log/openvpn', '/var/log/ipsec', '/var/log/strongswan',
            '/var/log/wireguard', '/var/log/tailscale', '/var/log/netbird'),
    'dns': ('/var/log/unbound', '/var/log/dnsmasq'),
    'dhcp': ('/var/log/dhcpd', '/var/log/kea', '/var/log/dnsmasq'),
    'ddns': ('/var/log/ddclient', '/var/log/dyndns'),
    'firmware': ('/var/log/firmware', '/var/log/pkg'),
    'backup': ('/var/log/cron', '/var/log/gdrive-backup', '/var/log/git-backup',
               '/var/log/yandexbackup'),
    'backend': ('/var/log/configd',),
    'firewall': ('/var/log/filter',),
    'ids': ('/var/log/suricata',),
}

# Plaintext logs, if present. No broad /var/log recursion or config scanning.
EXTRA_FILES = {
    'crowdsec': ('/var/log/crowdsec.log', '/var/log/crowdsec/crowdsec.log',
                 '/var/log/crowdsec/crowdsec-firewall-bouncer.log'),
    'ddns': ('/var/log/ddclient.log',),
}

SOURCE_SETTINGS = {
    'gateway': ('notifygatewaystatus', 'notifygatewayquality', 'notifywanip'),
    'auth': ('notifyauth',),
    'crowdsec': ('notifycrowdsec',),
    'vpn': ('notifyvpn',),
    'dns': ('notifydns',),
    'dhcp': ('notifydhcp', 'notifydhcpleases'),
    'ddns': ('notifyddnschanges', 'notifyddnserrors'),
    'firmware': ('notifyfirmware',),
    'backup': ('notifybackup',),
    'backend': ('notifybackend',),
    'firewall': ('notifyfirewall',),
    'ids': ('notifyids',),
}

# Whitelist identifiers: no URLs, query strings or uncontrolled text.
SAFE_NAME = re.compile(r'^[\w.:-]{1,90}$', re.ASCII)
IP_RE = re.compile(r'(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])')
ACCOUNT_RE = re.compile(r'\bAccount\s+[^\s]+\s+\[([a-zA-Z0-9_ .-]{1,72})\]', re.I)
HOST_RE = re.compile(r'\bhostname\s+([a-zA-Z0-9_.-]{2,110})', re.I)
MAC_RE = re.compile(r'\b(?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}\b')
UUID_RE = re.compile(r'[a-f0-9]{8}-[a-f0-9-]{20,}', re.I)


def flag(settings: dict[str, str], key: str, default: str = '1') -> bool:
    return settings.get(key, default).strip() == '1'


def accepted(settings: dict[str, str], category: str) -> bool:
    opt = FILTERS.get(category)
    return bool(opt and flag(settings, 'enabled', '0') and flag(settings, *opt))


def active_groups(settings: dict[str, str]) -> set[str]:
    return {group for group, keys in SOURCE_SETTINGS.items()
            if any(flag(settings, k, '0' if k in ('notifywanip', 'notifydhcpleases',
                                                'notifyfirewall', 'notifyids') else '1') for k in keys)}


def source_directories(settings: dict[str, str]) -> list[str]:
    groups = active_groups(settings)
    return list(dict.fromkeys(x for group in sorted(groups) for x in SOURCE_DIRS[group]))


def extra_files(settings: dict[str, str]) -> list[str]:
    groups = active_groups(settings)
    return list(dict.fromkeys(x for group in sorted(groups) for x in EXTRA_FILES.get(group, ())))


def hint_for(path: Path) -> str:
    value = str(path).lower()
    if value == '/var/log/crowdsec.log':
        return 'crowdsec'
    if value == '/var/log/ddclient.log':
        return 'ddns'
    for group, directories in SOURCE_DIRS.items():
        if any(value == d or value.startswith(d + '/') for d in directories):
            return group
    return 'system'


def has_program(line: str, *names: str) -> bool:
    """Match syslog program labels, avoiding arbitrary incidental mentions."""
    for name in names:
        # OPNsense RFC5424 (tag PID), BSD, or columnar UI formats.
        if re.search(r'(?:^|[\s])' + re.escape(name) +
                     r'(?:\[\d+\])?(?=[:\s])', line, re.I):
            return True
    return False


def contains(line: str, *patterns: str) -> bool:
    return any(re.search(p, line, re.I) for p in patterns)


def ip_from(line: str) -> str:
    for candidate in IP_RE.findall(line):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ''


def clean_name(name: str, default: str = '') -> str:
    return name if SAFE_NAME.fullmatch(name) else default


def event(service: str, category: str, detail: str, **extras) -> dict:
    return {'service': service, 'category': category, 'detail': detail, **extras}


# OPNsense configd includes the complete shell command in some failure logs.
# Never forward command arguments: they can contain tokens, passwords or URL
# parameters. Only the executable path (not its arguments) is considered safe.
BACKEND_EXECUTABLE = re.compile(r"(?:^|\s)(/[-A-Za-z0-9_./+]{2,220}|pkg|pluginctl|configctl|service)(?=\s|$)")
BACKEND_COMMAND = re.compile(r"\bCommand\s+'(.{1,1500}?)'\s+(?:returned|died|failed)\b", re.I)
BACKEND_EXIT = re.compile(r'\b(?:returned\s+non-zero\s+exit\s+status|exit\s+(?:status|code))\s+(\d{1,3})\b', re.I)
BACKEND_SIGNAL = re.compile(r'\bSignals\.([A-Z][A-Z0-9_]{1,25})(?::\s*\d+)?', re.I)
BACKEND_ACTION = re.compile(r'\baction\s+[\[\(]([a-zA-Z][a-zA-Z0-9_.-]{1,75})[\]\)]', re.I)


def _backend_program(line: str) -> str:
    """Return only a command's executable, excluding all parameters."""
    command = BACKEND_COMMAND.search(line)
    if not command:
        return ''
    raw = command.group(1).strip()
    # A quoted shell fragment or environment assignment cannot be safely
    # represented as one executable.
    match = BACKEND_EXECUTABLE.match(raw)
    if not match:
        return ''
    executable = match.group(1)
    if executable.startswith('/') and not executable.startswith(('/usr/local/', '/usr/bin/',
                                                                  '/usr/sbin/', '/bin/', '/sbin/')):
        return ''
    # Executing a Python interpreter: the script is much more useful to know.
    if executable.rsplit('/', 1)[-1] in ('python3', 'python3.11', 'python3.13'):
        rest = raw[match.end():].lstrip()
        script = BACKEND_EXECUTABLE.match(rest)
        if script and script.group(1).startswith('/usr/local/opnsense/scripts/'):
            executable = script.group(1)
    return executable


def _backend_component(program: str) -> str:
    if '/opnsense/scripts/' in program:
        part = program.split('/opnsense/scripts/', 1)[1].split('/', 1)[0]
        return clean_name(part, 'unknown')
    return clean_name(program.rsplit('/', 1)[-1], 'unknown') if program else ''


def _backend_details(line: str) -> tuple[str, str]:
    """Expose executable and a verified failure mode; never echo command args."""
    program = _backend_program(line)
    component = _backend_component(program)
    action = BACKEND_ACTION.search(line)
    details = []
    if program:
        details.append(f'Executable: {program}')
    elif action:
        details.append(f'Action: {action.group(1)}')
    if exit_code := BACKEND_EXIT.search(line):
        details.append(f'Result: process exited with code {exit_code.group(1)}')
    elif signal := BACKEND_SIGNAL.search(line):
        details.append(f'Result: process terminated by signal {signal.group(1)}')
    elif contains(line, r'\bpermission denied\b'):
        details.append('Result: permission denied')
    elif contains(line, r'\b(no such file|file not found)\b'):
        details.append('Result: required file or command was not found')
    elif contains(line, r'\b(timed out|timeout)\b'):
        details.append('Result: operation timed out')
    elif contains(line, r'\b(connection refused)\b'):
        details.append('Result: connection refused')
    else:
        details.append('Result: backend operation failed; see the original log for its cause')
    details.append('Log: System > Log Files > Backend')
    return component, '\n'.join(details)


def _crowdsec_component(line: str, path: Path) -> str:
    filename = path.name.lower()
    if 'bouncer' in filename or has_program(line, 'crowdsec-firewall-bouncer'):
        return 'CrowdSec firewall bouncer'
    if contains(line, r'\b(bouncer|remediation component)\b'):
        return 'CrowdSec firewall bouncer'
    if contains(line, r'\b(acquisition|datasource|parser)\b'):
        return 'CrowdSec log processor'
    return 'CrowdSec security engine'


def _crowdsec_reason(line: str) -> str:
    """Return only recognized error classifications, not the raw msg= payload."""
    # Order matters: specific failures before generic connection or config errors.
    if contains(line, r'\b(access forbidden|invalid api key|invalid credentials|wrong api key|'
                      r'authentication failed|authorization failed|unauthorized|401|403)\b'):
        return 'Authentication with the CrowdSec API was rejected. Check the bouncer or agent API key.'
    if contains(line, r'\b(connection refused|connect: connection refused|dial tcp[^\r\n]{0,100}refused)\b'):
        return 'Connection to the CrowdSec API was refused. Check that the Local API is running.'
    if contains(line, r'\b(timeout|timed out|deadline exceeded|context deadline exceeded)\b'):
        return 'The CrowdSec operation timed out. Check access to its API or log source.'
    if contains(line, r'\b(no such file or directory|file does not exist|file not found)\b'):
        return 'A required file or log source was not found. Check CrowdSec acquisition and configuration paths.'
    if contains(line, r'\b(permission denied|access is denied)\b'):
        return 'CrowdSec could not access a required resource (permission denied).'
    if contains(line, r'\b(failed to (?:parse|load)|parse error|invalid yaml|invalid configuration|'
                      r'cannot parse|could not parse|syntax error)\b'):
        return 'CrowdSec could not parse or load its configuration or input. Check the source log.'
    if contains(line, r'\b(failed to (?:insert|add|apply)|pfctl.*(?:error|failed)|firewall rule.*(?:error|failed))\b'):
        return 'CrowdSec could not apply a firewall decision. Check the remediation component.'
    if contains(line, r'\b(http (?:status )?5(?:00|02|03)|server error|internal server error)\b'):
        return 'A CrowdSec API server returned a server error.'
    return 'CrowdSec logged an error. Its exact cause cannot be safely identified from this entry.'


def _crowdsec_source(path: Path) -> str:
    # Show the actual selected journal path, not an untrusted value inside log.
    value = str(path)
    if value.startswith('/var/log/crowdsec/') or value == '/var/log/crowdsec.log':
        return value
    return 'Services > CrowdSec > Logs (or /var/log/crowdsec/)'


def classify(line: str, path: Path) -> dict | None:
    """Detect a small explicit subset of actionable service events.

    The watcher applies user filters separately; parsed events are not sent by
    themselves. A missing/unknown log pattern intentionally produces no alert.
    """
    line = line[:8192].strip()
    hint = hint_for(path)
    low = line.lower()

    # DDNS: both native 'Account <uuid> [service - backend]' and Perl ddclient.
    if (has_program(line, 'ddclient', 'ddclient_opn') or hint == 'ddns') and \
            (hint == 'ddns' or has_program(line, 'ddclient', 'ddclient_opn')):
        provider = ACCOUNT_RE.search(line)
        srv = 'Dynamic DNS' + (' (' + provider.group(1).strip() + ')' if provider else '')
        # Never relay full provider response / secret-bearing URL.
        if contains(low, r'\bnot modified\b', r'\bnochg\b', r'\bunchanged\b',
                    r'\bnot changed\b', r'\bno update (?:needed|required)\b'):
            return None
        errors = (
            (r'\b(badauth|unauthori[sz]ed|invalid credentials|authentication failed|401|403)\b', 'Provider rejected authentication'),
            (r'\b(no global ip|no public ip|cannot determine ip|ip address not detected)\b', 'Could not detect a public IP address'),
            (r'\b(error locating hostname|nohost|hostname not found)\b', 'DNS hostname could not be found'),
            (r'\b(timeout|timed out|connection refused|could not connect|unreachable)\b', 'Provider connection failed'),
            (r'\b(fail(?:ed|ure)?|error|warn(?:ing)?|invalid response|dnserr)\b', 'Dynamic DNS update reported an error'),
        )
        for pattern, reason in errors:
            if re.search(pattern, low):
                hostname = HOST_RE.search(line)
                host = clean_name(hostname.group(1)) if hostname else ''
                suffix = f' for {host}' if host else ''
                return event(srv, 'ddns_error', reason + suffix + '.')
        if contains(low, r'\b(successfully\s+updated|update\s+succeeded|updated\s+(?:ip|dns|record|hostname)|'
                         r'ip\s+address\s+(?:changed|updated)|good\b|record\s+has\s+been\s+updated|\baccount[^\r\n]{1,150}\bupdated)\b'):
            address = ip_from(line)
            return event(srv, 'ddns_changed', 'DNS record updated successfully' +
                         (f' (IP: {address})' if address else '') + '.')
        return None

    # Gateway dpinger alarms and clear transitions.
    if has_program(line, 'dpinger') or hint == 'gateway':
        # OPNsense gateway_watcher.php logs, for example:
        # dpinger: ALERT: WAN_DHCP (Addr: 1.1.1.1 Alarm: none -> down ...)
        transition = re.search(
            r'\b(?:ALERT|MONITOR):\s*([A-Za-z0-9_.:-]{2,75})\s*\('
            r'[^\r\n]{0,200}?\bAlarm:\s*'
            r'(none|up|online|down|force_down|delay|loss|delay\+loss)\s*->\s*'
            r'(none|up|online|down|force_down|delay|loss|delay\+loss)\b', line, re.I)
        if transition:
            gateway = clean_name(transition.group(1), 'Gateway')
            old, new = (x.lower() for x in transition.group(2, 3))
            if new in ('down', 'force_down'):
                return event(gateway, 'gateway_down', 'Gateway monitoring reports the connection is offline.')
            if old in ('down', 'force_down') and new not in ('down', 'force_down'):
                return event(gateway, 'gateway_up', 'Gateway monitoring reports the connection has recovered.')
            if new in ('delay', 'loss', 'delay+loss'):
                return event(gateway, 'gateway_quality', 'Gateway latency or packet loss exceeds its monitoring limit.')
            if old in ('delay', 'loss', 'delay+loss') and new in ('none', 'up', 'online'):
                return event(gateway, 'gateway_quality', 'Gateway latency and packet loss returned to normal.')
            return None
        match = re.search(r'\b(?:dpinger\s+)?([A-Za-z0-9_.:-]{2,75})\s+(?:alarm|clear)\b', line, re.I)
        gateway = clean_name(match.group(1), 'Gateway') if match else 'Gateway'
        if contains(low, r'\bclear\b', r'\bback online\b', r'\bgateway.*\bonline\b'):
            return event(gateway, 'gateway_up', 'Gateway monitoring alarm cleared; connection recovered.')
        if contains(low, r'\b(alarm|down|unreachable|packet loss 100%)\b'):
            if contains(low, r'\b(latency|loss|delay|jitter)\b') and not contains(low, r'\bdown\b', r'100%'):
                return event(gateway, 'gateway_quality', 'Gateway latency or packet loss exceeded its monitor limit.')
            return event(gateway, 'gateway_down', 'Gateway monitor reports an unavailable connection or severe packet loss.')
        return None

    # Login logs: never include attempted usernames or passwords.
    if has_program(line, 'sshd', 'lighttpd', 'webgui', 'login', 'php-fpm') or hint == 'auth':
        if contains(low, r'failed password', r'authentication failure', r'invalid user',
                    r'login failed', r'failed login', r'authentication failed'):
            src = ip_from(line)
            return event('Authentication', 'auth', 'Failed administrator/SSH authentication' +
                         (f' from {src}' if src else '') + '.')
        if contains(low, r'accepted (?:publickey|password)', r'login successful',
                    r'successful login', r'logged in successfully'):
            src = ip_from(line)
            return event('Authentication', 'auth', 'Successful administrator/SSH login' +
                         (f' from {src}' if src else '') + '.')

    # CrowdSec decisions and component errors are different event types.
    if has_program(line, 'crowdsec', 'crowdsec-firewall-bouncer') or hint == 'crowdsec':
        component = _crowdsec_component(line, path)
        if contains(low, r'\b(decision added|adding decision|new decision|ban applied|added ban)\b'):
            src = ip_from(line)
            return event(component, 'crowdsec_decision', 'A new security decision was applied' +
                         (f' to IP {src}' if src else '') + '.')
        if contains(low, r'\b(level=error|level=fatal|\berror\b|\bfatal\b)'):
            return event(component, 'crowdsec_error',
                         'Cause: ' + _crowdsec_reason(line) + '\nLog: ' + _crowdsec_source(path))
        return None

    # Explicit service-status transitions only, not routine tunnel chatter.
    vpn_names = ('openvpn', 'charon', 'strongswan', 'ipsec', 'wireguard', 'wg-quick',
                 'tailscaled', 'netbird', 'shadowsocks', 'ss-local')
    if has_program(line, *vpn_names) or hint == 'vpn':
        service = next((name for name in vpn_names if has_program(line, name)), 'VPN')
        if contains(low, r'\b(auth_failed|authentication failed|connection lost|peer disconnected|'
                         r'disconnected|inactivity timeout|reconnect failed|connection reset)\b'):
            return event(service, 'vpn_down', 'VPN connection lost or authentication failed.')
        if contains(low, r'\b(initialization sequence completed|connection established|'
                         r'peer connection initiated|connected to management|tunnel established)\b'):
            return event(service, 'vpn_up', 'VPN connection established or restored.')
        return None

    if has_program(line, 'unbound', 'dnsmasq', 'named') or hint == 'dns':
        if contains(low, r'\b(upstream|forwarder|forwarding|no servers|could not contact)\b.*'
                         r'\b(failed|unreachable|timeout|unavailable|refused)\b',
                    r'\b(failed to start|address already in use|could not bind|unable to bind)\b'):
            return event('DNS resolver', 'dns', 'DNS service or upstream resolver reported a failure.')

    if has_program(line, 'dnsmasq', 'dnsmasq-dhcp', 'kea-dhcp4', 'kea-dhcp6', 'dhcpd') or hint == 'dhcp':
        if contains(low, r'\b(no address(?:es)? available|subnet exhausted|lease allocation failed|'
                         r'dhcp.*failed|duplicate address|address conflict)\b'):
            return event('DHCP', 'dhcp', 'DHCP could not assign an address or detected a conflict.')
        if contains(line, r'\bDHCPACK\b', r'\bDHCP4_LEASE_ALLOC\b'):
            mac = MAC_RE.search(line)
            if mac:
                return event('DHCP', 'dhcp_lease', 'First observed DHCP lease for ' + mac.group(0).lower() + '.',
                             device=mac.group(0).lower())

    if has_program(line, 'dhclient', 'ppp', 'pppd') and \
            contains(low, r'bound to|new ip address|ip address changed'):
        addr = ip_from(line)
        if addr:
            return event('WAN address', 'wan_ip', f'Interface reported a new IP address: {addr}.')

    if has_program(line, 'pkg', 'opnsense-update', 'firmware') or hint == 'firmware':
        if contains(low, r'\b(update|upgrade|install)\b.*\b(failed|error|complete|successful)\b',
                    r'\b(upgrade failed|update completed)\b'):
            return event('Firmware', 'firmware', 'Firmware/package update ' +
                         ('reported a failure.' if contains(low, 'failed', 'error') else 'completed.'))

    if has_program(line, 'gdrive-backup', 'git-backup', 'yandexbackup', 'config-backup') or \
            (hint == 'backup' and contains(low, r'backup', r'git-backup', r'yandex')):
        if contains(low, r'\b(backup|upload|snapshot|push)\b.*\b(failed|error|unsuccessful)\b'):
            return event('Configuration backup', 'backup', 'Backup task failed; check backup logs.')

    if has_program(line, 'configd', 'configd.py') or hint == 'backend':
        if contains(low, r'\b(configuration|template|service|action|reload|backend)\b.*'
                         r'\b(failed|error|exception)\b') and not has_program(line, 'monit2max'):
            component, detail = _backend_details(line)
            return event('OPNsense backend' + (f' ({component})' if component else ''),
                         'backend', detail)

    # Optional firewall aggregation: never send individual blocked packets.
    if hint == 'firewall' and contains(low, r'\bblock\b'):
        return event('Firewall', 'firewall', 'Blocked firewall packets.', source_ip=ip_from(line))

    # Suricata EVE JSON, only known alert event type; signature not forwarded.
    if hint == 'ids' and line.startswith('{'):
        try:
            entry = json.loads(line)
            if entry.get('event_type') == 'alert' and isinstance(entry.get('alert'), dict):
                severity = entry['alert'].get('severity')
                if isinstance(severity, int) and severity <= 2:
                    src = clean_name(str(entry.get('src_ip', '')))
                    return event('IDS/IPS', 'ids', 'Suricata reported a high-severity alert' +
                                 (f' from {src}' if src else '') + '.')
        except (ValueError, TypeError, AttributeError):
            pass
    return None
