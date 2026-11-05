"""Regression checks for the private delivery test (not OPNsense syslog)."""
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock
import sys

SCRIPTS = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SCRIPTS))
import watcher
import monit2max


class DeliveryInboxTests(unittest.TestCase):
    def settings(self, **changed):
        data = {'enabled': '1', 'notifyfailures': '0', 'maxenabled': '1',
                'telegramenabled': '1', 'gotifyenabled': '1', 'title': 'OPNsense Notifications'}
        data.update(changed)
        return data

    def test_delivery_inbox_is_independent_of_every_system_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            testlog = Path(directory)/'private-test.log'
            settings = self.settings()
            state = watcher.load_state(Path(directory)/'state.json')
            with mock.patch.object(watcher, 'TEST_LOG', testlog), \
                 mock.patch.object(watcher, 'source_paths', return_value=[]):
                watcher.prepare_test_log()
                self.assertEqual(watcher.scan_sources(settings, state), 0)
                marker = uuid.uuid4().hex
                watcher.append_test_event(testlog, marker)
                self.assertEqual(watcher.scan_sources(settings, state), 1)
            self.assertTrue(state['probes'][marker]['accepted'])
            self.assertEqual(state['probes'][marker]['source'], str(testlog))
            self.assertEqual(state['queue'][0]['category'], 'test')
            self.assertEqual(len(state['queue'][0]['pending']), 3)

    def test_probe_only_complete_when_all_three_acknowledge(self):
        with tempfile.TemporaryDirectory() as directory:
            testlog = Path(directory)/'private-test.log'
            settings = self.settings()
            state = watcher.load_state(Path(directory)/'state.json')
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(settings, state, log=testlog)
                marker = uuid.uuid4().hex
                watcher.append_test_event(testlog, marker)
                watcher.scan_log(settings, state, log=testlog)
                calls = []
                def send(_settings, channel, _message):
                    calls.append(channel)
                    if channel == 'gotify' and calls.count('gotify') == 1:
                        raise monit2max.NotifyError('Temporary failure')
                with mock.patch.object(monit2max, 'deliver', side_effect=send):
                    watcher.flush_queue(settings, state)
                    self.assertFalse(state['probes'][marker]['sent'])
                    self.assertEqual(state['queue'][0]['pending'], ['gotify'])
                    state['queue'][0]['due_by']['gotify'] = 0
                    watcher.flush_queue(settings, state)
                self.assertTrue(state['probes'][marker]['sent'])
                self.assertEqual(calls, ['max', 'telegram', 'gotify', 'gotify'])
                self.assertFalse(state['queue'])

    def test_untrusted_or_malformed_lines_in_private_log_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            testlog = Path(directory)/'private-test.log'
            settings = self.settings()
            state = watcher.load_state(Path(directory)/'state.json')
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(settings, state, log=testlog)
                with testlog.open('a') as log:
                    log.write("monit[1]: 'RootFs' status failed (1)\n")
                    log.write('crowdsec[1]: error failed to start\n')
                    log.write("monit[0]: 'NOTIFICATION_DELIVERY_TEST' status failed (1) no marker\n")
                self.assertEqual(watcher.scan_log(settings, state, log=testlog), 0)
                self.assertFalse(state['queue'])

    def test_turned_off_destinations_report_helpful_error(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(maxenabled='0', telegramenabled='0', gotifyenabled='0')
            with mock.patch.object(monit2max, 'read_settings', return_value=settings), \
                 mock.patch.object(watcher, 'TEST_LOG', Path(directory)/'private-test.log'):
                result = watcher.pipeline_test(path=Path(directory)/'state.json', wait_seconds=0)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('MAX, Telegram or Gotify', result['message'])

    def test_diagnostic_script_not_dependent_on_syslog_logger(self):
        source = (SCRIPTS/'watcher.py').read_text()
        self.assertNotIn("'/usr/bin/logger'", source)
        self.assertNotIn('custom Event log path', source)
        self.assertIn('private test inbox', source)


if __name__ == '__main__':
    unittest.main()
