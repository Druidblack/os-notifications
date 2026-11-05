"""Multi-WAN state snapshots model OPNsense 26.7 gateway_status.php output."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SCRIPTS))
import gateway_monitor
import log_sources
import watcher


def gw(name='WAN_DHCP', status='none', delay='12.4 ms', loss='0.0 %', monitor='1.1.1.1'):
    return dict(name=name, status=status, address='192.0.2.1', monitor=monitor,
                delay=delay, loss=loss, stddev='0.8 ms')

class GatewayMonitorTests(unittest.TestCase):
    def setUp(self):
        self.state = {'gateway_states': {}}
        self.events = []
        self.callback = lambda name, category, detail: (self.events.append((name, category, detail)) or True)

    def update(self, snapshot, now):
        return gateway_monitor.update(self.state, snapshot, now, on_event=self.callback)

    def test_primary_and_backup_are_independent(self):
        both = {'WAN_DHCP': gw(), 'WAN_BACKUP': gw(name='WAN_BACKUP')}
        self.update(both, 1000)
        self.update({**both, 'WAN_BACKUP': gw(name='WAN_BACKUP', status='down', loss='100.0 %')}, 1012)
        self.assertEqual(self.events, [])
        self.update({**both, 'WAN_BACKUP': gw(name='WAN_BACKUP', status='down', loss='100.0 %')}, 1024)
        self.assertEqual([(x[0], x[1]) for x in self.events], [('WAN_BACKUP', 'gateway_down')])
        self.assertIn('Packet loss: 100.0 %', self.events[0][2])
        self.assertIn('Monitor target: 1.1.1.1', self.events[0][2])
        self.update(both, 1036)
        self.update(both, 1048)
        self.assertEqual(self.events[-1][:2], ('WAN_BACKUP','gateway_up'))
        self.assertIn('Offline duration: 24s', self.events[-1][2])

    def test_no_duplicate_after_poll_or_restart(self):
        s = {'GW_A': gw(status='down', loss='100.0 %')}
        self.update(s, 1000)
        self.update(s, 1012)
        self.update(s, 1024)
        self.update(s, 1036)
        self.assertEqual(len(self.events), 1)
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp)/'state.json'
            watcher.save_state(self.state, state_path)
            self.state = watcher.load_state(state_path)
            self.update(s, 1048)
        self.assertEqual(len(self.events), 1)

    def test_short_failure_does_not_alert(self):
        self.update({'GW': gw()}, 1000)
        self.update({'GW': gw(status='down')}, 1012)
        self.update({'GW': gw()}, 1024)
        self.assertFalse(self.events)

    def test_initial_offline_after_confirmation(self):
        self.update({'GW': gw(status='down', loss='100.0 %')}, 1000)
        self.update({'GW': gw(status='down', loss='100.0 %')}, 1012)
        self.assertEqual(self.events[0][1], 'gateway_down')

    def test_quality_change_and_recovery(self):
        self.update({'GW': gw()}, 1000)
        self.update({'GW': gw(status='delay', delay='450.0 ms')}, 1012)
        self.update({'GW': gw(status='delay', delay='450.0 ms')}, 1024)
        self.update({'GW': gw()}, 1036)
        self.update({'GW': gw()}, 1048)
        self.assertEqual([x[1] for x in self.events], ['gateway_quality', 'gateway_quality'])
        self.assertIn('returned to normal', self.events[-1][2])

    def test_down_to_degraded_is_recovered_but_still_high_latency(self):
        self.update({'GW': gw()}, 1000)
        self.update({'GW': gw(status='down')}, 1012)
        self.update({'GW': gw(status='down')}, 1024)
        self.update({'GW': gw(status='loss')}, 1036)
        self.update({'GW': gw(status='loss')}, 1048)
        self.assertEqual(self.events[-1][1], 'gateway_up')
        self.assertIn('still has excessive', self.events[-1][2])

    def test_invalid_response_and_monitor_disabled_are_ignored(self):
        self.assertIsNone(gateway_monitor.valid_gateway('GW', {'status': 'weird'}))
        self.assertIsNone(gateway_monitor.valid_gateway('GW', gw(loss='~')))
        self.assertIsNone(gateway_monitor.valid_gateway('../secret', gw()))
        self.update({'GW': gw(loss='~')}, 1000)
        self.assertFalse(self.state['gateway_monitor_active'])
        self.assertFalse(self.events)

    def test_disappearing_gateway_not_marked_offline(self):
        self.update({'GW': gw()}, 1000)
        self.update({}, 1012)
        self.assertFalse(self.events)
        self.assertNotIn('GW', self.state['gateway_states'])

    def test_status_command_reads_opnsense_json(self):
        with mock.patch.object(gateway_monitor.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps({'WAN': gw()}).encode()
            self.assertIn('WAN', gateway_monitor.read_status())
            self.assertEqual(run.call_args.args[0], [gateway_monitor.GATEWAY_STATUS_COMMAND])
            self.assertNotIn('shell', run.call_args.kwargs)

    def test_poll_integration_and_gateway_log_suppression(self):
        settings = {'enabled':'1', 'notifygatewaystatus':'1', 'notifygatewayquality':'1'}
        state = watcher.load_state(Path('/nonexistent/testing/state.json'))
        with mock.patch.object(gateway_monitor,'read_status', side_effect=[{'WAN':gw()},
                    {'WAN':gw(status='down', loss='100.0 %')},
                    {'WAN':gw(status='down', loss='100.0 %')}]), \
            mock.patch.object(watcher.monit2max, 'enabled_channels', return_value=['max']):
            watcher.poll_gateway_status(settings, state, now=1000, force=True)
            watcher.poll_gateway_status(settings, state, now=1012, force=True)
            watcher.poll_gateway_status(settings, state, now=1024, force=True)
        self.assertEqual(len(state['queue']), 1)
        self.assertTrue(watcher.gateway_status_is_current(state, now=1024))
        self.assertFalse(watcher.gateway_status_is_current(state, now=1080))
        with tempfile.TemporaryDirectory() as td:
            file = Path(td)/'latest.log'
            file.write_text('')
            watcher.scan_log(settings,state,log=file)
            file.write_text('dpinger: ALERT: WAN (Addr: 1.1.1.1 Alarm: none -> down RTT: 0 Loss: 100%)\n')
            # Test at realistic epoch: old timestamps should let fallback work.
            self.assertEqual(watcher.scan_log(settings,state,log=file), 1)

    def test_poll_error_keeps_last_known_state_and_allows_syslog_fallback(self):
        settings = {'enabled':'1', 'notifygatewaystatus':'1'}
        state = watcher.load_state(Path('/nonexistent/testing/state.json'))
        with mock.patch.object(gateway_monitor, 'read_status', return_value={'GW': gw()}):
            watcher.poll_gateway_status(settings, state, now=1000, force=True)
        with mock.patch.object(gateway_monitor, 'read_status', side_effect=OSError('failed')):
            watcher.poll_gateway_status(settings, state, now=1100, force=True)
        self.assertFalse(state['gateway_monitor_active'])
        self.assertEqual(state['gateway_states']['GW']['condition'], 'online')

    def test_actual_gateway_watcher_transition(self):
        path = Path('/var/log/gateways/latest.log')
        samples = [('none -> down', 'gateway_down'), ('down -> none', 'gateway_up'),
                   ('none -> loss', 'gateway_quality'), ('loss -> none', 'gateway_quality')]
        for transition, expected in samples:
            message = f'dpinger[55]: ALERT: WAN_DHCP (Addr: 1.1.1.1 Alarm: {transition} RTT: 20.0 RTTd: 0.5 Loss: 10.0)'
            with self.subTest(transition=transition):
                obj = log_sources.classify(message, path)
                self.assertIsNotNone(obj)
                self.assertEqual(obj['category'],expected)
                self.assertEqual(obj['service'], 'WAN_DHCP')

if __name__ == '__main__':
    unittest.main()
