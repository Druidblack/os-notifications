"""FreeBSD CPU temperature alert and recovery handling, including UI wiring."""
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, mock
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SCRIPTS))
import cpu_temperature as cpu
import watcher


class SensorTests(TestCase):
    def test_only_real_cpu_mibs_used_and_highest_selected(self):
        sample = '''dev.cpu.1.temperature: 58.0C\nhw.acpi.thermal.tz0.temperature: 0.1C\n'''
        sample += 'dev.cpu.0.temperature: 65.5C\n' + 'dev.cpu.2.temperature: -1.0C\n'
        self.assertEqual(cpu.parse_sensors(sample),
                         {'dev.cpu.0.temperature': 65.5, 'dev.cpu.1.temperature': 58.0})

    def test_invalid_and_other_mibs_are_ignored(self):
        sample = ('dev.cpu.0.temperature: 150.0C\n'
                  'dev.cpu.1.temperature: nanC\n'
                  'dev.cpu.2.coretemp.tjmax: 100.0C\n'
                  'dev.cpu.3.temperature: 0.1C\n'
                  'dev.cpu.4.temperature: 44C\n')
        self.assertEqual(cpu.parse_sensors(sample), {'dev.cpu.4.temperature': 44})

    def test_read_sysctl_command_without_shell(self):
        with mock.patch.object(cpu.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = 'dev.cpu.0.temperature: 37.0C\n'
            self.assertEqual(cpu.read_sensors(), {'dev.cpu.0.temperature': 37})
            self.assertEqual(run.call_args.args[0], ['/sbin/sysctl', '-a'])
            self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_missing_sensors_not_silent_success(self):
        with mock.patch.object(cpu.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = 'hw.acpi.thermal.tz0.temperature: 0.1C\n'
            with self.assertRaisesRegex(ValueError, 'No CPU temperature'):
                cpu.read_sensors()

    def test_one_alarm_and_one_recovery_with_hysteresis(self):
        state = {}
        events = []
        report = lambda n, c, d: (events.append((n,c,d)) or True)
        samples = [(1000, 74), (1020, 81), (1040, 83), (1060, 80),
                   (1080, 72), (1100, 71), (1120, 76), (1140, 70), (1160, 69)]
        for now, temperature in samples:
            cpu.update(state, {'dev.cpu.0.temperature': temperature}, 75, now, report)
        self.assertEqual([e[1] for e in events],
                         ['cpu_temperature_high', 'cpu_temperature_recovered'])
        self.assertIn('83.0 °C', events[0][2])
        self.assertIn('Hottest sensor: CPU 0', events[0][2])
        self.assertFalse(state['cpu_temperature_state']['alert_active'])

    def test_confirmation_count_does_not_carry_across_long_sleep(self):
        state = {}
        events = []
        cb = lambda n, c, d: (events.append(c) or True)
        cpu.update(state, {'dev.cpu.0.temperature': 80}, 75, 1000, cb)
        cpu.update(state, {'dev.cpu.0.temperature': 80}, 75, 1500, cb)
        self.assertFalse(events)
        cpu.update(state, {'dev.cpu.0.temperature': 80}, 75, 1520, cb)
        self.assertEqual(events, ['cpu_temperature_high'])

    def test_alarm_survives_persistent_state_and_does_not_repeat(self):
        state = {}
        events = []
        cb = lambda n, c, d: (events.append(c) or True)
        sample = {'dev.cpu.0.temperature': 82}
        cpu.update(state, sample, 75, 1000, cb)
        cpu.update(state, sample, 75, 1020, cb)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'state.json'
            watcher.save_state(state, path)
            state = watcher.load_state(path)
            cpu.update(state, sample, 75, 1040, cb)
        self.assertEqual(events, ['cpu_temperature_high'])
        self.assertTrue(state['cpu_temperature_state']['alert_active'])

    def test_form_model_template_and_watcher_are_connected(self):
        model = ROOT/'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml'
        forms = ROOT/'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms/temperature.xml'
        root = ET.parse(model).getroot()
        self.assertIsNotNone(root.find('./items/general/CpuTempEnabled'))
        field = root.find('./items/general/CpuTempThreshold')
        self.assertEqual(field.findtext('./Default'), '75')
        self.assertEqual(field.findtext('./MaximumValue'), '105')
        f = ET.parse(forms).getroot()
        self.assertEqual(len(f.findall('field')), 2)
        template = (ROOT/'src/opnsense/service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        self.assertIn('CpuTempEnabled={{', template)
        self.assertIn('CpuTempThreshold={{', template)
        view = (ROOT/'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt').read_text()
        self.assertIn("'id': 'frm_Temperature'", view)
        self.assertIn("'frm_Temperature': '/api/monit2max/settings/get'", view)

    def test_watcher_enqueues_temperature_alarm_and_recovery(self):
        state = {'queue': [], 'recent': {}}
        settings = {'enabled': '1', 'cputempenabled': '1', 'cputempthreshold': '75'}
        values = iter([{'dev.cpu.0.temperature': 81.0},
                       {'dev.cpu.0.temperature': 83.0},
                       {'dev.cpu.0.temperature': 68.0},
                       {'dev.cpu.0.temperature': 68.0}])
        with mock.patch.object(cpu, 'read_sensors', side_effect=lambda: next(values)), \
             mock.patch.object(watcher.monit2max, 'enabled_channels', return_value=['max', 'telegram']):
            for timestamp in (1000, 1020, 1040, 1060):
                watcher.poll_cpu_temperature(settings, state, now=timestamp, force=True)
        self.assertEqual([x['category'] for x in state['queue']],
                         ['cpu_temperature_high', 'cpu_temperature_recovered'])
        self.assertEqual(state['queue'][0]['pending'], ['max','telegram'])
        message = watcher.build_message({'title': 'OPNsense'}, state['queue'][0])
        self.assertIn('CPU temperature warning', message)
        self.assertIn('83.0 °C', message)

    def test_disabled_option_does_not_query_sysctl(self):
        with mock.patch.object(cpu, 'read_sensors') as mock_read:
            self.assertEqual(watcher.poll_cpu_temperature({'cputempenabled': '0'}, {}, now=100), 0)
            mock_read.assert_not_called()

    def test_unavailable_sensors_keep_alarm_and_report_error(self):
        record = {'alert_active': True, 'alarm_since': 100}
        state = {'cpu_temperature_state': record, 'queue': []}
        with mock.patch.object(cpu, 'read_sensors', side_effect=ValueError('No CPU temperature sensors found')):
            watcher.poll_cpu_temperature({'cputempenabled':'1','cputempthreshold':'75'}, state, now=200, force=True)
        self.assertTrue(record['alert_active'])
        self.assertIn('No valid CPU temperature', record['error'])
        self.assertEqual(len(state['queue']), 0)

    def test_too_many_sensors_message_is_bounded(self):
        sample = {f'dev.cpu.{i}.temperature': i/10 + 50 for i in range(128)}
        message = cpu.details(sample, 'dev.cpu.127.temperature', 62.7, 75)
        self.assertIn('and 112 more sensors', message)
        self.assertNotIn('CPU 127: ', message)
