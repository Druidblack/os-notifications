"""Opt-in diagnostic excerpts must not break event filters, queue or secrets."""
import configparser
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(HERE))
import log_sources
import monit2max
import safe_log
import watcher


class OriginalLogOptionTests(unittest.TestCase):
    def settings(self, enabled='1'):
        return {'enabled': '1', 'maxenabled': '1', 'telegramenabled': '1',
                'includeoriginallog': enabled,
                'notifyfailures': '1', 'notifycrowdsec': '1',
                'notifybackend': '1', 'notifyddnserrors': '1',
                'notifyfirewall': '1', 'title': 'OPNsense Monit'}

    def create_event(self, settings, line, hint=None):
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / 'latest.log'
            log.write_text('')
            state = watcher.load_state(Path(t) / 'state.json')
            if hint is None:
                watcher.scan_log(settings, state, log=log)
                with log.open('a') as f:
                    f.write(line + '\n')
                added = watcher.scan_log(settings, state, log=log)
            else:
                with mock.patch.object(log_sources, 'hint_for', return_value=hint):
                    watcher.scan_log(settings, state, log=log)
                    with log.open('a') as f:
                        f.write(line + '\n')
                    added = watcher.scan_log(settings, state, log=log)
            return added, state

    def test_config_fields_default_off_and_backward_compatible(self):
        model = ET.parse(ROOT / 'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml')
        field = model.find('.//IncludeOriginalLog')
        self.assertEqual(field.attrib['type'], 'BooleanField')
        self.assertEqual(field.findtext('Default'), '0')
        form = (ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms/notifications.xml').read_text()
        template = (ROOT / 'src/opnsense/service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        self.assertIn('monit2max.general.IncludeOriginalLog', form)
        self.assertIn('IncludeOriginalLog=', template)
        self.assertIn("default('0')", template.split('IncludeOriginalLog=', 1)[1].split('\n')[0])
        self.assertFalse(watcher.enabled({'enabled': '1'}, 'includeoriginallog', '0'))

    def test_no_original_by_default_for_monit_and_backend(self):
        line = "monit[42]: '$HOST' memory usage of 82% matches resource limit [memory usage > 75%]"
        added, state = self.create_event(self.settings(enabled='0'), line)
        self.assertEqual(added, 1)
        self.assertNotIn('original_log', state['queue'][0])
        message = watcher.build_message(self.settings(enabled='0'), state['queue'][0])
        self.assertNotIn('Original log message', message)

    def test_monit_includes_actual_event_line_when_enabled(self):
        line = "2026-11-04 monit[42]: '$HOST' cpu usage of 83% matches resource limit [cpu usage > 75%]"
        added, state = self.create_event(self.settings(), line)
        self.assertEqual(added, 1)
        msg = watcher.build_message(self.settings(), state['queue'][0])
        self.assertIn('Event: Health check problem', msg)
        self.assertIn('Original log message (redacted):', msg)
        self.assertIn('cpu usage of 83% matches resource limit', msg)

    def test_backend_command_keeps_failure_but_no_arguments(self):
        line = ("configd.py: Script action failed with Command "
                "'/usr/local/opnsense/scripts/unbound/wrapper.py --token=VERYSECRET -s' "
                "returned non-zero exit status 127.")
        added, state = self.create_event(self.settings(), line, 'backend')
        self.assertEqual(added, 1)
        queued = state['queue'][0]
        self.assertNotIn('VERYSECRET', str(queued))
        msg = watcher.build_message(self.settings(), queued)
        self.assertIn('Original log message', msg)
        self.assertIn('wrapper.py [arguments hidden]', msg)
        self.assertIn('exit status 127', msg)
        self.assertNotIn('--token', msg)

    def test_crowdsec_original_error_includes_diagnostic_text(self):
        line = ('level=error msg="auth-api: unable to connect: dial tcp 127.0.0.1:8080: '
                'connect: connection refused" token=superSECRET')
        added, state = self.create_event(self.settings(), line, 'crowdsec')
        self.assertEqual(added, 1)
        msg = watcher.build_message(self.settings(), state['queue'][0])
        self.assertIn('Cause: Connection to the CrowdSec API was refused', msg)
        self.assertIn('dial tcp 127.0.0.1:8080', msg)
        self.assertNotIn('superSECRET', msg)
        self.assertIn('token=[hidden]', msg)

    def test_ddns_source_included_when_enabled(self):
        line = ('ddclient: WARNING: Provider connection timeout for hostname dyn.example.com '
                'token=myddnspassword')
        added, state = self.create_event(self.settings(), line, 'ddns')
        self.assertEqual(added, 1)
        msg = watcher.build_message(self.settings(), state['queue'][0])
        self.assertIn('Dynamic DNS failure', msg)
        self.assertIn('Provider connection timeout', msg)
        self.assertNotIn('myddnspassword', msg)

    def test_both_channels_receive_same_safe_message_and_retry(self):
        line = 'monit[21]: \'gateway_alert\' status failed (1) -- gateway unreachable'
        settings = self.settings()
        _, state = self.create_event(settings, line)
        sent = []
        def collect(_s, channel, message):
            sent.append((channel, message))
        with mock.patch.object(monit2max, 'deliver', side_effect=collect):
            self.assertEqual(watcher.flush_queue(settings, state), 2)
        self.assertEqual({x[0] for x in sent}, {'max', 'telegram'})
        self.assertEqual(sent[0][1], sent[1][1])
        self.assertIn('Original log message', sent[0][1])
        self.assertEqual(state['queue'], [])

    def test_toggling_option_off_hides_queued_original(self):
        line = "monit[1]: '$HOST' cpu usage of 88% matches resource limit [cpu usage > 75%]"
        _, state = self.create_event(self.settings(), line)
        self.assertIn('original_log', state['queue'][0])
        msg = watcher.build_message(self.settings(enabled='0'), state['queue'][0])
        self.assertNotIn('Original log message', msg)

    def test_sensitive_formats_are_redacted(self):
        samples = [
            ('password="private value"', 'private value'),
            ("'token':'PRIVATEVALUE'", 'PRIVATEVALUE'),
            ('"api_key":"SENSITIVE"', 'SENSITIVE'),
            ('--password SECRET123', 'SECRET123'),
            ('--api-key=SECRET123', 'SECRET123'),
            ('Authorization: Bearer SECRET123', 'SECRET123'),
            ('Authorization Bearer SECRET123', 'SECRET123'),
            ('https://user:pass@example.org/api?token=SECRET123', 'SECRET123'),
            ('ftp://username:secret@example.org/path', 'secret'),
            ('123456789:MYTELEGRAMTOKEN123456789', 'MYTELEGRAMTOKEN123456789'),
            ('access_token=MYACCESSTOKEN123', 'MYACCESSTOKEN123'),
            ('Cookie: user_session=ABC123', 'ABC123'),
            ('opaque_' + 'abc123' * 12, 'abc123abc123'),
        ]
        for entry, secret in samples:
            with self.subTest(entry=entry):
                self.assertNotIn(secret, safe_log.sanitize('error ' + entry))

    def test_control_chars_and_truncation(self):
        raw = 'error: aborted\nService: fake\x1b[31m' + ('some descriptive error text ' * 180)
        value = safe_log.sanitize(raw)
        self.assertNotIn('\n', value)
        self.assertNotIn('\x1b', value)
        self.assertLessEqual(len(value), safe_log.EXCERPT_LIMIT)
        self.assertTrue(value.endswith('[truncated]'))

    def test_no_original_on_lifecycle_event(self):
        event = {'category': 'shutdown', 'service': 'OPNsense',
                 'detail': 'The system is shutting down.', 'created': 1000}
        msg = watcher.build_message(self.settings(), event)
        self.assertNotIn('Original log message', msg)

    def test_firewall_summary_includes_only_one_safe_example(self):
        s = self.settings()
        state = watcher.load_state(Path('/does-not-exist-file.json'))
        entry = {'source_ip': '192.0.2.1'}
        for i in range(12):
            watcher.add_firewall_hit(state, entry, 1000+i, original_log='filterlog: block 192.0.2.1 token=SECRET')
        self.assertFalse(watcher.emit_firewall_summary(s, state, now=1200))
        self.assertTrue(watcher.emit_firewall_summary(s, state, now=1400))
        self.assertEqual(len(state['queue']), 1)
        msg = watcher.build_message(s, state['queue'][0])
        self.assertIn('Blocked 12 logged packets', msg)
        self.assertIn('filterlog: block 192.0.2.1', msg)
        self.assertNotIn('SECRET', msg)


if __name__ == '__main__':
    unittest.main()
