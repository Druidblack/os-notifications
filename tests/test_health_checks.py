"""Read-only health probes, transitions, old-settings compatibility and UI wiring."""
import base64
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, mock
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SCRIPTS))
import health_checks as hc
import watcher


class HealthChecks(TestCase):
    def test_off_by_default_and_no_commands(self):
        state = {}
        with mock.patch.object(hc, 'smart_measurements') as smart, mock.patch.object(hc, 'resource_measurements') as res:
            self.assertEqual(hc.poll({}, state, lambda *a: True, now=1000), 0)
        smart.assert_not_called(); res.assert_not_called()

    def test_alert_after_two_samples_and_one_recovery(self):
        values = iter([True, True, True, False, False])
        events = []
        row = {}
        for _ in range(5):
            bad = next(values)
            hc.state_transition(row, 'swap', bad, 'Swap', 'Swap 90%', 'Swap normal',
                                lambda *a: (events.append(a) or True))
        self.assertEqual([item[1] for item in events], ['check_problem', 'check_recovered'])

    def test_independent_groups_continue_after_failure(self):
        settings = {'smartenabled':'1', 'resourcesenabled':'1'}
        state = {}
        def bad_smart(s): raise OSError('smartctl not installed')
        with mock.patch.object(hc, 'smart_measurements', side_effect=bad_smart), \
             mock.patch.object(hc, 'resource_measurements', return_value=[('swap', True, 'Swap high')]):
            hc.poll(settings, state, lambda *a: True, now=1000)
            hc.poll(settings, state, lambda *a: True, now=2000)
        self.assertIn('error', state['health_checks']['storage'])
        self.assertTrue(state['health_checks']['resources']['items']['swap']['bad'])

    def test_smart_devices_and_health(self):
        sample = {'smart_status': {'passed':False},
                  'nvme_smart_health_information_log': {'percentage_used': 94, 'critical_warning': 1},
                  'temperature': {'current': 64}}
        process = mock.Mock(stdout=json.dumps(sample), returncode=0)
        with mock.patch.object(hc.Path, 'is_file', return_value=True), \
             mock.patch.object(hc, 'command', return_value=json.dumps({'devices':[{'name':'/dev/nvme0','type':'nvme'}]})), \
             mock.patch.object(hc.subprocess,'run', return_value=process) as run:
            result = hc.smart_measurements({'smartwearlimit':'90'})
        self.assertEqual(result[0][0], '/dev/nvme0')
        self.assertTrue(result[0][1])
        self.assertIn('94%', result[0][2])
        self.assertEqual(run.call_args.args[0], ['/usr/local/sbin/smartctl','-a','-j','/dev/nvme0','-d','nvme'])

    def test_pf_state_usage_parsing(self):
        def command(args, **kw):
            if 'swapinfo' in args[0]: return 'Device 1K-blocks Used Avail Capacity\nTotal 100 81 19 81%\n'
            if 'pfctl' in args[0] and '-si' in args: return 'State Table\n  current entries 81\n'
            if 'pfctl' in args[0]: return 'states hard limit 100\n'
            return '5/10/15/100 mbuf clusters in use (current/cache/total/max)'
        with mock.patch.object(hc,'command', side_effect=command):
            result = hc.resource_measurements({'swaplimit':'80','pflimit':'80'})
        self.assertEqual([row[1] for row in result], [True,True,False])

    def test_alias_table_missing_and_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            config=folder/'config.xml'
            config.write_text('''<opnsense><OPNsense><Firewall><Alias><aliases>
              <alias><enabled>1</enabled><name>GeoIP_Test</name><type>urltable</type></alias>
              <alias><enabled>1</enabled><name>Unused</name><type>external</type></alias>
              </aliases></Alias></Firewall></OPNsense></opnsense>''')
            result=hc.alias_measurements({}, config, folder, now=100000)
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0][1])
            table=folder/'GeoIP_Test.txt';table.write_text('192.0.2.1\n')
            with mock.patch.object(hc.time,'time',return_value=100000):
                result=hc.alias_measurements({},config,folder,now=100000)
            self.assertFalse(result[0][1])
            import os
            os.utime(table, (1000,1000))
            result=hc.alias_measurements({},config,folder,now=1000000)
            self.assertTrue(result[0][1])

    def test_certificate_milestones_and_recovery(self):
        state={}; events=[]
        emit=lambda *args: (events.append(args) or True)
        for days in [31,29,29,6,0,-2,90,90]:
            level=30 if days <= 30 else 0
            if days <= 7: level=7
            if days <= 1: level=1
            if days < 0: level=-1
            hc.cert_transitions(state, [('certref',days<=30, str(days),level)],emit)
        self.assertEqual([e[1] for e in events],
                         ['check_problem']*4+['check_recovered'])

    def test_certificate_read_from_config_and_never_send_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'config.xml'
            pem='-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n'
            encoded=base64.b64encode(pem.encode()).decode()
            path.write_text('<opnsense><system><webgui><ssl-certref>id1</ssl-certref></webgui></system>'
                            f'<cert><refid>id1</refid><descr>GUI</descr><crt>{encoded}</crt></cert></opnsense>')
            with mock.patch.object(hc,'command',return_value='notAfter=Dec 01 00:00:00 2027 GMT') as cmd:
                values=hc.certificate_measurements({},path,now=dt.datetime(2027,11,15,tzinfo=dt.timezone.utc).timestamp())
            self.assertEqual(values[0][3],30)
            self.assertEqual(cmd.call_args.kwargs['input_data'],pem)
            self.assertNotIn('BEGIN CERTIFICATE',values[0][2])

    def test_backup_freshness_is_local_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp); filename=folder/'config-123.xml';filename.write_text('<x/>')
            import os
            os.utime(filename,(1000,1000))
            rows=hc.backup_measurements({'backupdirectory':tmp,'backupagedays':'2'},now=1000+3*86400)
            self.assertTrue(rows[0][1]);self.assertIn('does not verify uploads',rows[0][2])

    def test_watcher_message_labels_and_model_form(self):
        for category in ('check_problem','check_recovered'):
            event={'service':'resource','category':category,'detail':'Sample','created':0}
            self.assertIn('System health',watcher.build_message({},event))
        model = ET.parse(ROOT/'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml').getroot()
        template = (ROOT/'src/opnsense/service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        for field in ('SmartEnabled','ResourcesEnabled','AliasEnabled','CertEnabled','BackupFreshnessEnabled'):
            self.assertIsNotNone(model.find('./items/general/'+field))
            self.assertIn(field+'={{',template)
        view=(ROOT/'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt').read_text()
        self.assertIn("'frm_Hardware': '/api/monit2max/settings/get'",view)
        self.assertIn("'id': 'frm_Hardware'",view)


    def test_poll_to_notification_queue_all_channels(self):
        state = {'queue':[], 'recent':{}}
        settings = {'enabled':'1','resourcesenabled':'1'}
        sample = [('swap', True, 'Swap usage 95% exceeds 80%')]
        cb = lambda service, category, detail: watcher.enqueue(
            state, service, category, detail, channels=['max','telegram','gotify'], cooldown=0)
        with mock.patch.object(hc, 'resource_measurements', return_value=sample):
            hc.poll(settings, state, cb, now=1000, force=True)
            hc.poll(settings, state, cb, now=1060, force=True)
        self.assertEqual(len(state['queue']), 1)
        self.assertEqual(state['queue'][0]['category'], 'check_problem')
        self.assertEqual(state['queue'][0]['pending'], ['max','telegram','gotify'])
        self.assertIn('Swap usage 95%', watcher.build_message({'title':'OPNsense'},state['queue'][0]))

    def test_removed_checks_absent_from_schema_template_and_form(self):
        model_path = ROOT/'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml'
        model = ET.parse(model_path).getroot()
        template = (ROOT/'src/opnsense/service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        form_path = ROOT/'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms/services.xml'
        form = ET.parse(form_path).getroot()
        for key in ('DnsProbeEnabled','DnsTargets','DnsDomain','BackupSource'):
            self.assertIsNone(model.find('./items/general/'+key))
            self.assertNotIn(key+'=',template)
            self.assertFalse(any(n.findtext('id') == 'monit2max.general.'+key
                                 for n in form.findall('field')))
        # Retain log-based DNS errors and log-based backup task errors.
        self.assertIsNotNone(model.find('./items/general/NotifyDns'))
        self.assertIsNotNone(model.find('./items/general/NotifyBackup'))

    def test_removed_dns_check_not_polled_even_if_old_config_enabled(self):
        state={'health_checks':{'dns_probe':{'enabled':True,'error':'old DNS error'}}}
        hc.poll({'dnsprobeenabled':'1','dnstargets':'127.0.0.1:53'},state,
                lambda *args: self.fail('unexpected event'), now=1000, force=True)
        self.assertNotIn('dns_probe',state['health_checks'])
        self.assertNotIn('dns_probe',hc.POLL)

    def test_legacy_git_source_does_not_read_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'new-backup.xml';path.write_text('<config/>')
            with mock.patch.object(hc, 'command', side_effect=AssertionError('Git command called')):
                result=hc.backup_measurements({'backupsource':'git','backupdirectory':tmp,
                                               'backupagedays':'2'},now=path.stat().st_mtime)
            self.assertEqual(result[0][0], 'Local configuration backup')
            self.assertFalse(result[0][1])

    def test_stale_git_backup_history_cleared_from_state(self):
        state={'health_checks':{'backups':{'items':{'Local Git backup history':{'bad':True}}}}}
        hc.poll({}, state, lambda *args: True, now=1000)
        self.assertNotIn('Local Git backup history',state['health_checks']['backups']['items'])

    def test_no_remote_configuration_actions(self):
        self.assertNotIn('configctl', (SCRIPTS/'health_checks.py').read_text())
        self.assertNotIn('shell=True',(SCRIPTS/'health_checks.py').read_text())
