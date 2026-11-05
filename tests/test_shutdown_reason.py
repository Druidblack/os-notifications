"""Offline tests for FreeBSD shutdown intent and notification formatting."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SRC))
import shutdown_intent
import watcher
import monit2max


class ShutdownReasonTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 4, 12, 20, 0, tzinfo=dt.timezone.utc).timestamp()

    def log(self, directory: Path, text: str, *, stamp: float | None = None) -> Path:
        file = directory / 'latest.log'
        file.write_text(text, encoding='utf-8')
        os.utime(file, (self.now if stamp is None else stamp,) * 2)
        return file

    def test_reboot_is_detected_from_official_freebsd_shutdown_log(self):
        line = '2026-11-04T12:19:58+00:00 fw shutdown[213]: reboot by root: '
        self.assertEqual(shutdown_intent.classify_line(line, now=self.now)[0], 'restart')

    def test_power_off_is_not_classified_as_restart(self):
        line = '2026-11-04T12:19:58+00:00 fw shutdown[214]: power-down by root: '
        self.assertEqual(shutdown_intent.classify_line(line, now=self.now)[0], 'shutdown')

    def test_halt_and_power_cycle(self):
        a = '2026-11-04T12:19:58+00:00 fw shutdown: halt by root:'
        b = '2026-11-04T12:19:58+00:00 fw shutdown: power-cycle by root:'
        self.assertEqual(shutdown_intent.classify_line(a, now=self.now)[0], 'shutdown')
        self.assertEqual(shutdown_intent.classify_line(b, now=self.now)[0], 'restart')

    def test_plain_shutdown_reports_unknown(self):
        a = '2026-11-04T12:19:58+00:00 fw shutdown[11]: shutdown by root:'
        self.assertEqual(shutdown_intent.classify_line(a, now=self.now)[0], 'unknown')

    def test_old_and_future_entries_not_used(self):
        old = '2026-11-04T12:10:00+00:00 fw shutdown[1]: reboot by root:'
        future = '2026-11-04T12:22:00+00:00 fw shutdown[1]: reboot by root:'
        self.assertIsNone(shutdown_intent.classify_line(old, now=self.now))
        self.assertIsNone(shutdown_intent.classify_line(future, now=self.now))

    def test_no_fuzzy_match_from_plugin_or_other_service(self):
        lines = [
            '2026-11-04T12:19:58+00:00 fw monit[3]: shutdown reboot by root:',
            '2026-11-04T12:19:58+00:00 fw shell: shutdown reboot by root:',
            '2026-11-04T12:19:58+00:00 fw configd[3]: reboot by root:',
            '2026-11-04T12:19:58+00:00 fw shutdown[3]: normal operations',
        ]
        for line in lines:
            self.assertIsNone(shutdown_intent.classify_line(line, now=self.now))

    def test_legacy_bsd_timestamp(self):
        local = dt.datetime.fromtimestamp(self.now)
        line = f"{local.strftime('%b %e %H:%M:%S')} fw shutdown[99]: reboot by root:"
        self.assertEqual(shutdown_intent.classify_line(line, now=self.now)[0], 'restart')

    def test_most_recent_valid_record_wins(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            p1 = base / 'auth.log'
            p1.write_text('2026-11-04T12:19:50+00:00 fw shutdown: reboot by root:\n')
            p2 = base / 'system.log'
            p2.write_text('2026-11-04T12:19:58+00:00 fw shutdown: power-down by root:\n')
            for path in (p1, p2):
                os.utime(path, (self.now, self.now))
            self.assertEqual(shutdown_intent.detect_reason(paths=(str(p1), str(p2)),
                                                            now=self.now), 'shutdown')

    def test_file_mtime_and_unparseable_timestamp(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            old = self.log(base, '2026-11-04T12:19:58+00:00 shutdown: reboot by root:',
                           stamp=self.now-600)
            self.assertEqual(shutdown_intent.detect_reason(paths=(old,),now=self.now),'unknown')
            self.log(base, 'shutdown: reboot by root:')
            self.assertEqual(shutdown_intent.detect_reason(paths=(old,),now=self.now),'unknown')

    def test_missing_sources(self):
        self.assertEqual(shutdown_intent.detect_reason(paths=('/does/not/exist',),now=self.now),'unknown')

    def test_real_lifecycle_dispatch_uses_shutdown_reason(self):
        settings = {'enabled': '1', 'notifyshutdown': '1', 'title': 'OPNsense Notifications',
                    'provider': 'official', 'recipienttype':'user', 'recipientid':'1',
                    'token': 'abc'}
        captured = []
        def deliver(s, channel, text, **kwargs):
            captured.append(text)
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(monit2max, 'read_settings', return_value=settings), \
             mock.patch.object(monit2max, 'enabled_channels', return_value=['max']), \
             mock.patch.object(monit2max, 'deliver', side_effect=deliver):
            for reason, expected in [('restart', 'System restart'),
                                     ('shutdown', 'System shutdown'),
                                     ('unknown', 'System stopping')]:
                with mock.patch.object(shutdown_intent, 'detect_reason', return_value=reason):
                    marker = Path(td)/'stop-notification.json'
                    marker.unlink(missing_ok=True)  # independent simulated boot
                    self.assertEqual(watcher.lifecycle('shutdown', path=Path(td)/'state.json')['status'], 'ok')
                self.assertIn(expected, captured[-1])
                self.assertNotIn('shutting down or rebooting normally', captured[-1])

    def test_gui_reboot_detected_before_shutdown_log_exists(self):
        parents = {
            601: (590, '/usr/local/bin/python3 /usr/local/opnsense/scripts/OPNsense/Monit2Max/watcher.py --shutdown'),
            590: (588, '/bin/sh /usr/local/etc/rc.syshook.d/stop/10-monit2max'),
            588: (580, '/bin/sh /usr/local/etc/rc.syshook stop'),
            580: (44, '/bin/sh /usr/local/etc/rc.reboot'),
        }
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=601, reader=parents.get), 'restart')

    def test_gui_poweroff_detected_before_shutdown_log_exists(self):
        parents = {
            601: (590, '/bin/sh /usr/local/etc/rc.syshook.d/stop/10-monit2max'),
            590: (588, '/bin/sh /usr/local/etc/rc.syshook stop'),
            588: (44, '/bin/sh /usr/local/etc/rc.halt'),
        }
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=601, reader=parents.get), 'shutdown')

    def test_process_commands_are_exact_script_paths(self):
        invalid = [
            '/bin/sh /tmp/not-rc.reboot',
            '/bin/sh /tmp/rc.halt',
            '/bin/sh /usr/local/etc/rc.reboot.old',
            '/bin/sh /usr/local/etc/rc.reboot-not-really',
            'python3 watcher.py --message=rc.reboot',
            'python3 watcher.py --shutdown',
            '/bin/sh /usr/local/etc/rc.shutdown',
            '/bin/bash -lc "echo /usr/local/etc/rc.reboot"',
        ]
        for command in invalid:
            self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=901,
                            reader={901:(1,command)}.get), 'unknown', command)

    def test_direct_official_script_without_shell_prefix(self):
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=10,
                         reader={10:(1,'/usr/local/etc/rc.reboot')}.get), 'restart')
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=10,
                         reader={10:(1,'/usr/local/etc/rc.halt')}.get), 'shutdown')

    def test_process_tree_cycle_or_missing_pid_is_safe(self):
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=22,
                        reader={22:(23,'sh'),23:(22,'python')}.get), 'unknown')
        self.assertEqual(shutdown_intent.detect_from_process_tree(start_pid=22,
                        reader={}.get), 'unknown')

    def test_process_is_prioritized_over_old_log(self):
        with mock.patch.object(shutdown_intent, 'detect_from_process_tree', return_value='restart'):
            self.assertEqual(shutdown_intent.detect_reason(paths=('/nonexistent',), now=self.now), 'restart')

    def test_process_reader_parses_freebsd_ps(self):
        result = mock.Mock(returncode=0, stdout='  588 /bin/sh /usr/local/etc/rc.reboot\n')
        with mock.patch.object(shutdown_intent.subprocess, 'run', return_value=result) as run:
            self.assertEqual(shutdown_intent.parent_command(589), (588,'/bin/sh /usr/local/etc/rc.reboot'))
            self.assertIn('-ww',run.call_args.args[0])

    def test_same_boot_stop_hook_sends_each_channel_only_once(self):
        settings = {'enabled':'1','notifyshutdown':'1','title':'OPNsense Notifications'}
        sent = []
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(monit2max, 'read_settings', return_value=settings), \
             mock.patch.object(monit2max, 'enabled_channels', return_value=['max','telegram','gotify']), \
             mock.patch.object(monit2max, 'deliver', side_effect=lambda s,c,msg,**kw: sent.append((c,msg))), \
             mock.patch.object(watcher,'current_boot_identity',return_value='boot1'), \
             mock.patch.object(shutdown_intent,'detect_reason',return_value='restart'):
            path = Path(td)/'state.json'
            self.assertEqual(watcher.lifecycle('shutdown',path=path)['status'],'ok')
            self.assertEqual(watcher.lifecycle('shutdown',path=path)['status'],'ok')
            self.assertEqual([c for c,m in sent],['max','telegram','gotify'])
            self.assertTrue(all('System restart' in msg for c,msg in sent))

    def test_stop_failure_retries_only_missing_channel(self):
        settings = {'enabled':'1','notifyshutdown':'1','title':'OPNsense Notifications'}
        sent = []
        fail = [True]
        def deliver(s, channel, message, **kwargs):
            if channel == 'telegram' and fail[0]:
                raise monit2max.NotifyError('Unavailable')
            sent.append(channel)
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(monit2max,'read_settings',return_value=settings), \
             mock.patch.object(monit2max,'enabled_channels',return_value=['max','telegram']), \
             mock.patch.object(monit2max,'deliver',side_effect=deliver), \
             mock.patch.object(watcher,'current_boot_identity',return_value='boot1'), \
             mock.patch.object(shutdown_intent,'detect_reason',return_value='shutdown'):
            path=Path(td)/'state.json'
            self.assertEqual(watcher.lifecycle('shutdown',path=path)['status'],'failed')
            fail[0] = False
            self.assertEqual(watcher.lifecycle('shutdown',path=path)['status'],'ok')
            self.assertEqual(sent,['max','telegram'])

    def test_new_boot_can_notify_again(self):
        settings = {'enabled':'1','notifyshutdown':'1','title':'OPNsense Notifications'}
        sent=[]
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(monit2max,'read_settings',return_value=settings), \
             mock.patch.object(monit2max,'enabled_channels',return_value=['max']), \
             mock.patch.object(monit2max,'deliver',side_effect=lambda s,c,m,**kw:sent.append(c)), \
             mock.patch.object(watcher,'current_boot_identity',side_effect=['boot1','boot2']), \
             mock.patch.object(shutdown_intent,'detect_reason',return_value='restart'):
            path=Path(td)/'state.json'
            watcher.lifecycle('shutdown',path=path)
            watcher.lifecycle('shutdown',path=path)
            self.assertEqual(sent,['max','max'])


if __name__ == '__main__':
    unittest.main()
