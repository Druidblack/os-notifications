import importlib.util
import json
import uuid
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SCRIPTS))
import monit2max
import watcher

class WatcherTests(unittest.TestCase):
    def settings(self):
        return {'enabled': '1', 'provider': 'a161', 'token': 'abc123',
                'recipienttype': 'user', 'recipientid': '12345', 'title': 'OPNsense Monit',
                'notifyfailures': '1', 'notifyrecoveries': '1',
                'notifyactions': '1', 'notifystartup': '1', 'notifyshutdown': '1'}

    def test_identifies_event_and_recovery_and_action(self):
        prefix = '2026-11-03T23:20:00+0300 monit[1122]: '
        event = watcher.parse_monit_event(prefix + "'gateway_alert' status failed (1) -- no response")
        self.assertEqual((event['service'], event['category']), ('gateway_alert', 'failure'))
        self.assertEqual(watcher.parse_monit_event(prefix+"'gateway_alert' status succeeded (0)")['category'], 'recovery')
        self.assertEqual(watcher.parse_monit_event(prefix+"'web' restart action done")['category'], 'action')
        self.assertIsNone(watcher.parse_monit_event('myapp[1122]: monit subsystem status failed'))
        self.assertIsNone(watcher.parse_monit_event('monit[22]: Poll cycle started'))
        self.assertEqual(watcher.parse_monit_event("monit[22]: 'carp_status_change' status changed")['category'], 'other')

    def test_monit_own_log_format(self):
        line = "[2026-11-03T21:30:00+0300] info : 'gateway_alert' status succeeded (0)"
        self.assertIsNone(watcher.parse_monit_event(line))
        self.assertEqual(watcher.parse_monit_event(line, direct=True)['category'], 'recovery')

    def test_filter_switches(self):
        s = self.settings()
        self.assertTrue(watcher.accepted(s, 'failure'))
        s['notifyrecoveries'] = '0'
        self.assertFalse(watcher.accepted(s, 'recovery'))
        self.assertTrue(watcher.accepted(s, 'action'))
        s['enabled'] = '0'
        self.assertFalse(watcher.accepted(s, 'failure'))

    def test_start_at_end_and_detect_new_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp)/'latest.log'
            log.write_text("monit[2]: 'test' status failed (1)\n")
            state = watcher.load_state(Path(tmp)/'state.json')
            self.assertEqual(watcher.scan_log(self.settings(), state, log=log), 0)
            with log.open('a') as fh:
                fh.write("2026-11-03 monit[8]: 'gateway_alert' status failed (1) -- down\n")
            self.assertEqual(watcher.scan_log(self.settings(), state, log=log), 1)
            self.assertEqual(state['queue'][0]['category'], 'failure')
            self.assertEqual(watcher.scan_log(self.settings(), state, log=log), 0)

    def test_rotated_log_is_read_from_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp)/'latest.log'; log.write_text('')
            state = watcher.load_state(Path(tmp)/'state.json')
            watcher.scan_log(self.settings(), state, log=log)
            old = Path(tmp)/'old.log'; log.rename(old)
            log.write_text("monit: 'RootFs' status succeeded (0)\n")
            self.assertEqual(watcher.scan_log(self.settings(), state, log=log), 1)

    def test_dedup_and_persistent_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = watcher.load_state(Path(tmp)/'state.json')
            self.assertTrue(watcher.enqueue(state,'gw','failure','down',now=1000))
            self.assertFalse(watcher.enqueue(state,'gw','failure','down',now=1001))
            path=Path(tmp)/'state.json'
            watcher.save_state(state,path)
            self.assertEqual(watcher.load_state(path)['queue'][0]['service'],'gw')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_retry_does_not_drop_pending_on_failure(self):
        state=watcher.load_state(Path('/no/such/test'))
        watcher.enqueue(state,'gateway','failure','down',now=1000)
        with mock.patch.object(monit2max,'enforce_rate_limit'), mock.patch.object(monit2max,'send_message',side_effect=monit2max.NotifyError('HTTP 403')):
            self.assertEqual(watcher.flush_queue(self.settings(),state,now=1001),0)
        self.assertEqual(len(state['queue']),1)
        self.assertGreater(state['queue'][0]['due'],1001)
        with mock.patch.object(monit2max,'enforce_rate_limit'), mock.patch.object(monit2max,'send_message') as send:
            self.assertEqual(watcher.flush_queue(self.settings(),state,now=state['queue'][0]['due']+1),1)
            self.assertTrue(send.called)
        self.assertEqual(state['queue'],[])

    def test_shutdown_timeout_and_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self.settings()
            with mock.patch.object(monit2max,'read_settings',return_value=settings), mock.patch.object(monit2max,'send_message') as send:
                self.assertEqual(watcher.lifecycle('shutdown',path=Path(tmp)/'state.json')['status'],'ok')
                self.assertEqual(send.call_args.kwargs['timeout'],5)

    def test_startup_enqueues_once_per_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'state.json'
            with mock.patch.object(monit2max,'read_settings',return_value=self.settings()):
                with mock.patch.object(watcher.os,'popen') as get_boot:
                    get_boot.return_value.read.return_value='fixed-boot-time'
                    watcher.lifecycle('startup',path=path)
                    watcher.lifecycle('startup',path=path)
            self.assertEqual(len(watcher.load_state(path)['queue']),1)


    def test_resource_limit_cpu_ram_disk(self):
        sample = [
            ("monit[1]: '$HOST' cpu usage of 82% matches resource limit [cpu usage > 75%]", 'failure'),
            ("monit[1]: '$HOST' memory usage of 84% matches resource limit [memory usage > 75%]", 'failure'),
            ("monit[1]: 'RootFs' space usage of 78% matches resource limit [space usage > 75%]", 'failure'),
            ("monit[1]: '$HOST' cpu usage check succeeded [current cpu usage = 5%]", 'recovery'),
            ("2026-11-03T23:20:00 host monit 123 - - 'gateway_alert' status failed (1)", 'failure'),
        ]
        for line, category in sample:
            with self.subTest(line=line):
                self.assertEqual(watcher.parse_monit_event(line)['category'], category)

    def test_probe_tracks_real_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            testlog = Path(tmp) / 'delivery-test.log'
            state = watcher.load_state(Path(tmp) / 'state.json')
            settings = self.settings()
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(settings, state, log=testlog)
                probe = uuid.uuid4().hex
                watcher.append_test_event(testlog, probe)
                self.assertEqual(watcher.scan_log(settings, state, log=testlog), 1)
                self.assertTrue(state['probes'][probe]['accepted'])
                self.assertFalse(state['probes'][probe]['sent'])
                self.assertEqual(state['queue'][0]['category'], 'test')
                with mock.patch.object(monit2max, 'enforce_rate_limit'), mock.patch.object(monit2max, 'send_message'):
                    self.assertEqual(watcher.flush_queue(settings, state), 1)
                self.assertTrue(state['probes'][probe]['sent'])
                self.assertTrue(watcher.marker_in_log(testlog, probe))
                self.assertEqual(testlog.stat().st_mode & 0o777, 0o600)
                self.assertEqual(testlog.parent.stat().st_mode & 0o777, 0o700)

    def test_probe_missing_journal_reports_failure_not_false_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            testlog = Path(tmp) / 'delivery-test.log'
            state_file = Path(tmp) / 'state.json'
            state = watcher.load_state(state_file)
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(self.settings(), state, log=testlog)
                watcher.save_state(state, state_file)
                with mock.patch.object(monit2max, 'read_settings', return_value=self.settings()), \
                     mock.patch.object(watcher.subprocess, 'run') as logger:
                    result = watcher.pipeline_test(path=state_file, wait_seconds=0)
                logger.assert_not_called()  # No syslog routing is required.
                self.assertEqual(result['status'], 'failed')
                self.assertIn('did not process it', result['message'])
                self.assertTrue(testlog.read_text())

    def test_probe_without_cursor_refuses_to_claim_journal_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            testlog = Path(tmp) / 'delivery-test.log'
            with mock.patch.object(watcher, 'TEST_LOG', testlog), \
                 mock.patch.object(monit2max, 'read_settings', return_value=self.settings()), \
                 mock.patch.object(watcher.time, 'sleep'):
                result = watcher.pipeline_test(path=Path(tmp) / 'missing.json', wait_seconds=0)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('not initialized', result['message'])

    def test_probe_filter_does_not_block_delivery_test(self):
        # Testing the channel is allowed even if real problem notifications are off.
        with tempfile.TemporaryDirectory() as tmp:
            settings = self.settings()
            settings['notifyfailures'] = '0'
            testlog = Path(tmp)/'delivery-test.log'
            state = watcher.load_state(Path(tmp)/'state.json')
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(settings, state, log=testlog)
                watcher.append_test_event(testlog, uuid.uuid4().hex)
                self.assertEqual(watcher.scan_log(settings, state, log=testlog), 1)
                self.assertEqual(state['queue'][0]['category'], 'test')

    def test_upgrade_no_restore_endpoint_or_script(self):
        base = Path(__file__).resolve().parents[1]
        self.assertNotIn('restoreAction', (base / 'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/Api/ServiceController.php').read_text())
        self.assertNotIn('[restore]', (base / 'src/opnsense/service/conf/actions.d/actions_monit2max.conf').read_text())
        self.assertFalse((base/'src/opnsense/scripts/OPNsense/Monit2Max/restore_monit_actions.php').exists())
        self.assertNotIn('restoreAct', (base/'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt').read_text())


    def test_pipeline_reports_success_only_after_actual_queue_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            testlog = root/'delivery-test.log'
            path = root/'state.json'
            state = watcher.load_state(path)
            settings = self.settings()
            with mock.patch.object(watcher, 'TEST_LOG', testlog):
                watcher.prepare_test_log()
                watcher.scan_log(settings, state, log=testlog)
                watcher.save_state(state, path)
                def run_watch_cycle(seconds):
                    current = watcher.load_state(path)
                    watcher.scan_log(settings, current, log=testlog)
                    with mock.patch.object(monit2max, 'enforce_rate_limit'), \
                         mock.patch.object(monit2max, 'send_message') as send:
                        watcher.flush_queue(settings, current)
                        if current.get('probes'):
                            send.assert_called_once()
                    watcher.save_state(current, path)
                with mock.patch.object(monit2max, 'read_settings', return_value=settings), \
                     mock.patch.object(watcher.time, 'sleep', side_effect=run_watch_cycle), \
                     mock.patch.object(watcher.subprocess, 'run') as logger:
                    result = watcher.pipeline_test(path=path, wait_seconds=2)
                logger.assert_not_called()
                self.assertEqual(result['status'], 'ok')
                self.assertIn('Verified:', result['message'])
                self.assertIn('does not test routing', result['message'])

    def test_auto_log_discovers_monit_and_system_journals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            monit_dir=root/'monit'; monit_dir.mkdir()
            system_dir=root/'system'; system_dir.mkdir()
            (monit_dir/'latest.log').write_text('')
            (system_dir/'latest.log').write_text('')
            with mock.patch.object(watcher, 'AUTO_LOG_DIRS', (str(monit_dir), str(system_dir))), \
                 mock.patch.object(watcher, 'AUTO_LOG_FILES', ()):
                actual=watcher.source_paths({'logfile':'auto'})
                self.assertEqual(actual, [monit_dir/'latest.log', system_dir/'latest.log'])
                old=watcher.source_paths({'logfile':watcher.DEFAULT_LOG})
                self.assertEqual(old,actual)

    def test_two_journals_have_independent_cursors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            syslog=root/'system.log'; syslog.write_text('historical\n')
            monit=root/'monit.log'; monit.write_text('historical\n')
            with mock.patch.object(watcher, 'source_paths', return_value=[monit, syslog]), \
                 mock.patch.object(watcher, 'TEST_LOG', root/'missing-delivery-test.log'):
                settings=self.settings()
                state=watcher.load_state(root/'state.json')
                self.assertEqual(watcher.scan_sources(settings,state), 0)
                with monit.open('a') as f: f.write("monit[1]: 'CPU' cpu usage of 85% matches resource limit\n")
                with syslog.open('a') as f: f.write("monit[1]: 'Router' status failed (1)\n")
                self.assertEqual(watcher.scan_sources(settings,state), 2)
                self.assertEqual(watcher.scan_sources(settings,state), 0)
                self.assertEqual(len(state['queue']), 2)
                self.assertEqual(set(state['cursors']), {str(syslog),str(monit)})

    def test_new_source_after_initial_scan_starts_at_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            syslog=root/'system.log'; syslog.write_text('')
            newlog=root/'monit.log'; newlog.write_text("monit: 'old' status failed (1)\n")
            settings=self.settings()
            state=watcher.load_state(root/'state.json')
            watcher.scan_log(settings,state,log=syslog)
            self.assertEqual(watcher.scan_log(settings,state,log=newlog), 0)
            with newlog.open('a') as fd: fd.write("monit: 'new' status failed (1)\n")
            self.assertEqual(watcher.scan_log(settings,state,log=newlog), 1)
            self.assertEqual(state['queue'][0]['service'], 'new')

    def test_legacy_system_cursor_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            log=Path(tmp)/'test.log'
            first="monit: 'old' status failed (1)\n"
            log.write_text(first)
            st=log.stat()
            state={'queue': [],'recent': {}, 'cursor': {'id':f'{st.st_dev}:{st.st_ino}', 'offset':len(first)}, 'cursors':{}}
            with mock.patch.object(watcher,'DEFAULT_LOG',str(log)):
                with log.open('a') as fd: fd.write("monit: 'new' status failed (1)\n")
                self.assertEqual(watcher.scan_log(self.settings(),state,log=log),1)
                self.assertEqual(state['queue'][0]['service'],'new')

    def test_auto_handles_daily_file_without_latest_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); folder=root/'monit'; folder.mkdir()
            old=folder/'monit_20261031.log'; old.write_text('old')
            latest=folder/'monit_20261103.log'; latest.write_text('new')
            # Ensure deterministic mtimes.
            import os
            os.utime(old, (100, 100))
            os.utime(latest, (200, 200))
            with mock.patch.object(watcher,'AUTO_LOG_DIRS',(str(folder),)), \
                 mock.patch.object(watcher,'AUTO_LOG_FILES',()):
                self.assertEqual(watcher.source_paths({'logfile':'auto'}), [latest])

if __name__ == '__main__': unittest.main()
