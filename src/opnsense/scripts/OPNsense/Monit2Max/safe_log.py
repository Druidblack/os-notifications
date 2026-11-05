#!/usr/local/bin/python3
"""Best-effort privacy filtering for *opt-in* diagnostic journal excerpts.

Never store or send the unsanitized log text in the notification queue. Log
records can contain arbitrary secrets; the excerpt is therefore deliberately
short, strips complete URLs and hides command arguments as well as common
credential representations. This is not a general-purpose secret scanner.
"""
from __future__ import annotations

import re
import unicodedata

EXCERPT_LIMIT = 1100

# Syslog can include quoted commands with secret-bearing CLI arguments.
COMMAND = re.compile(r"\bCommand\s+'(.{1,1500}?)'\s+(returned|died|failed)\b", re.I)
SAFE_PROGRAM = re.compile(r'^(?:/[-a-zA-Z0-9_./+]{1,220}|pkg|pluginctl|configctl|service)$')
SCRIPT = re.compile(r'(/usr/local/opnsense/scripts/[-a-zA-Z0-9_./+]{1,220})')
URL = re.compile(r'(?i)\b(?:https?|ftp|wss?)://[^\s<>"\']+')
BOT_TOKEN = re.compile(r'(?<![\w])\d{5,}:[A-Za-z0-9_-]{12,}(?![\w])')
BEARER = re.compile(r'(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}={0,2}')
SENSITIVE_KEY = (r'(?:password|passwd|passphrase|pwd|token|access[_-]?token|'
                 r'refresh[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|'
                 r'private[_-]?key|authorization|cookie|set-cookie|session[_-]?id|'
                 r'auth[_-]?token|credential(?:s)?)')
# Separate quoted and unquoted forms; preserve the field name in the output.
CREDENTIAL_ASSIGNMENT = re.compile(
    r'(?i)(?<![\w-])(?:[\'\"]?)(?P<key>' + SENSITIVE_KEY +
    r')(?P<q>[\'\"]?)\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;}\]]+)',
)
CREDENTIAL_FLAG = re.compile(
    r'(?i)(?P<flag>--' + SENSITIVE_KEY +
    r')(?:=|\s+)(?:"[^"]*"|\'[^\']*\'|[^\s,;}\]]+)',
)
# Some loggers emit header fields without an equals sign.
AUTH_HEADER = re.compile(r'(?i)\b(?:authorization|proxy-authorization)\s*(?:[:=]\s*|\s+)(?:bearer|basic)\s+[^\s,;]+')
OPAQUE_SECRET = re.compile(r'(?<![\w])(?=[A-Za-z0-9_\-]{52,}(?![\w]))(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]+')


def _command_without_arguments(match: re.Match[str]) -> str:
    command, status = match.groups()
    parts = command.strip().split(None, 1)
    executable = parts[0] if parts else ''
    if not SAFE_PROGRAM.fullmatch(executable):
        return f"Command '[command hidden]' {status}"
    if executable.rsplit('/', 1)[-1].startswith('python'):
        script = SCRIPT.search(command)
        if script:
            executable = script.group(1)
    suffix = ' [arguments hidden]' if len(parts) > 1 else ''
    return f"Command '{executable}{suffix}' {status}"


def sanitize(line: str, *, limit: int = EXCERPT_LIMIT) -> str:
    """Return one bounded, readable and partially redacted journal record."""
    # Avoid control characters/newline injection (including Unicode format chars).
    value = ''.join(ch if unicodedata.category(ch) not in ('Cc', 'Cf', 'Cs') else ' '
                    for ch in str(line)).strip()
    value = re.sub(r'\s+', ' ', value)
    value = COMMAND.sub(_command_without_arguments, value)
    value = URL.sub('[URL hidden]', value)
    value = BOT_TOKEN.sub('[bot token hidden]', value)
    value = AUTH_HEADER.sub('[authorization header hidden]', value)
    value = BEARER.sub('[authorization hidden]', value)
    value = CREDENTIAL_ASSIGNMENT.sub(lambda m: f"{m.group('key')}=[hidden]", value)
    value = CREDENTIAL_FLAG.sub(lambda m: f"{m.group('flag')}=[hidden]", value)
    value = OPAQUE_SECRET.sub('[opaque value hidden]', value)
    if not value:
        return ''
    limit = max(80, min(int(limit), EXCERPT_LIMIT))
    if len(value) > limit:
        return value[:limit - len(' … [truncated]')].rstrip() + ' … [truncated]'
    return value
