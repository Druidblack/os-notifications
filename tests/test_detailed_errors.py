"""Actionable, conservative log error explanations without leaking secrets.

Samples mimic known OPNsense configd/CrowdSec output, not real user logs.
"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(HERE))
import log_sources
import watcher
import monit2max


class DetailedErrors(unittest.TestCase):
    BACKEND = Path('/var/log/configd/latest.log')
    CROWDSEC = Path('/var/log/crowdsec/crowdsec.log')
    BOUNCER = Path('/var/log/crowdsec/crowdsec-firewall-bouncer.log')

    def parse(self, msg, path=None):
        return log_sources.classify(msg, path or self.BACKEND)

    def test_configd_reports_executable_and_code(self):
        line = ("2026-11-04T07:48:29 Error configd.py [f34fb567-56f2-4914-89ce-51af5feb2e2f] "
                "Script action failed with Command '/usr/local/opnsense/scripts/unbound/wrapper.py -s ' "
                "returned non-zero exit status 1. at Traceback (most recent call last)")
        event = self.parse(line)
        self.assertEqual(event['category'], 'backend')
        self.assertEqual(event['service'], 'OPNsense backend (unbound)')
        self.assertIn('Executable: /usr/local/opnsense/scripts/unbound/wrapper.py', event['detail'])
        self.assertIn('code 1', event['detail'])
        self.assertIn('System > Log Files > Backend', event['detail'])
        self.assertNotIn('Traceback', event['detail'])

    def test_configd_does_not_leak_command_arguments(self):
        line = ("configd.py: Script action failed with Command "
                "'/usr/local/opnsense/scripts/syslog/queryLog.py --filter https://example.test/?token=PRIVATE "
                "--password VERYSECRET' returned non-zero exit status 7. Exception: stderr bearer HIDDEN")
        event = self.parse(line)
        self.assertEqual(event['service'], 'OPNsense backend (syslog)')
        self.assertIn('code 7', event['detail'])
        for secret in ('PRIVATE', 'VERYSECRET', 'HIDDEN', '--filter', 'bearer'):
            self.assertNotIn(secret, str(event))

    def test_configd_signal(self):
        line = ("configd.py [123456]: Script action failed with Command "
                "'/usr/local/sbin/pluginctl -S' died with <Signals.SIGSEGV: 11>.")
        event = self.parse(line)
        self.assertEqual(event['service'], 'OPNsense backend (pluginctl)')
        self.assertIn('SIGSEGV', event['detail'])
        self.assertNotIn(' -S', event['detail'])

    def test_backend_generic_never_fakes_a_service(self):
        line = 'configd.py: configuration reload failed with exception token=SECRET'
        event = self.parse(line)
        self.assertEqual(event['service'], 'OPNsense backend')
        self.assertIn('cause', event['detail'])
        self.assertNotIn('SECRET', str(event))

    def test_command_with_untrusted_shell_cannot_be_reported(self):
        line = ("configd.py: Script action failed with Command "
                "'SECRET=whatever bash -c something' returned non-zero exit status 2")
        event = self.parse(line)
        self.assertEqual(event['service'], 'OPNsense backend')
        self.assertNotIn('SECRET', str(event))
        self.assertIn('code 2', event['detail'])

    def test_bouncer_connection_refused(self):
        msg = ('time="2026-11-04T07:56:17+03:00" level=error '
               'msg="auth-api: auth with api key failed return nil response, '
               'error: dial tcp 127.0.0.1:8080: connect: connection refused"')
        event = self.parse(msg, self.BOUNCER)
        self.assertEqual(event['category'], 'crowdsec_error')
        self.assertEqual(event['service'], 'CrowdSec firewall bouncer')
        self.assertIn('Connection to the CrowdSec API was refused', event['detail'])
        self.assertIn(str(self.BOUNCER), event['detail'])

    def test_crowdsec_invalid_api_key(self):
        event = self.parse('time="..." level=error msg="API error: access forbidden"', self.BOUNCER)
        self.assertEqual(event['category'], 'crowdsec_error')
        self.assertIn('API key', event['detail'])

    def test_crowdsec_missing_file(self):
        event = self.parse('level=error msg="failed to read file: no such file or directory"', self.CROWDSEC)
        self.assertEqual(event['service'], 'CrowdSec security engine')
        self.assertIn('log source was not found', event['detail'])

    def test_crowdsec_unknown_error_does_not_echo_secrets(self):
        event = self.parse('level=error msg="https://host?password=SECRET token=ABCD crash"', self.CROWDSEC)
        self.assertIn('exact cause cannot be safely identified', event['detail'])
        self.assertNotIn('SECRET', str(event))
        self.assertNotIn('ABCD', str(event))

    def test_decision_is_not_misreported_as_error(self):
        event = self.parse('level=info msg="new decision" ip=203.0.113.4', self.CROWDSEC)
        self.assertEqual(event['category'], 'crowdsec_decision')
        self.assertIn('203.0.113.4', event['detail'])
        self.assertNotIn('error', event['detail'].lower())

    def test_existing_filter_still_controls_both_crowdsec_categories(self):
        s = {'enabled': '1', 'notifycrowdsec': '0'}
        self.assertFalse(log_sources.accepted(s, 'crowdsec_error'))
        self.assertFalse(log_sources.accepted(s, 'crowdsec_decision'))
        s['notifycrowdsec'] = '1'
        self.assertTrue(log_sources.accepted(s, 'crowdsec_error'))
        self.assertTrue(log_sources.accepted(s, 'crowdsec_decision'))

    def test_messages_have_different_event_titles(self):
        settings = {'title': 'OPNsense Monit'}
        def message(category):
            return watcher.build_message(settings, {'category':category,'service':'CrowdSec',
                                                     'detail':'Test', 'created':1000})
        self.assertIn('Event: CrowdSec service error', message('crowdsec_error'))
        self.assertIn('Event: CrowdSec security decision', message('crowdsec_decision'))
        self.assertIn('Event: Backend action failed', message('backend'))

    def test_new_event_pipeline_through_queue(self):
        s={'enabled':'1', 'maxenabled':'1', 'notifybackend':'1', 'notifycrowdsec':'1'}
        state=watcher.load_state(Path('/no-such-test-file'))
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'latest.log'
            f.write_text('')
            with patch.object(log_sources,'hint_for',return_value='backend'):
                watcher.scan_log(s,state,log=f)
                with f.open('a') as h:
                    h.write("configd.py: Script action failed with Command '/usr/local/sbin/pkg upgrade' returned non-zero exit status 1.\n")
                self.assertEqual(watcher.scan_log(s,state,log=f),1)
            with patch.object(monit2max,'deliver') as deliver:
                self.assertEqual(watcher.flush_queue(s,state),1)
                self.assertIn('Executable: /usr/local/sbin/pkg',deliver.call_args.args[2])
                self.assertNotIn('upgrade',deliver.call_args.args[2])

if __name__=='__main__':
    unittest.main()
