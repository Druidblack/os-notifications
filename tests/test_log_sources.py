"""Synthetic OPNsense log excerpts; no external services or system changes."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(HERE))
import log_sources as src
import watcher
import monit2max


class ExtraSourcesTests(unittest.TestCase):
    def log(self, msg, group='system'):
        return src.classify(msg, Path('/var/log') / group / 'latest.log')

    def test_ddns_native_errors_and_success(self):
        error = self.log('2026-03-16 Error ddclient Account 91f8db9b [cloudflare - opnsense] error locating hostname host.example.com [A]', 'ddclient')
        self.assertEqual(error['category'], 'ddns_error')
        self.assertIn('cloudflare', error['service'])
        self.assertIn('host.example.com', error['detail'])
        success = self.log('2026-03-16 Notice ddclient Account 91f8db9b [cloudflare - opnsense] successfully updated DNS record to 203.0.113.5', 'ddclient')
        self.assertEqual(success['category'], 'ddns_changed')
        self.assertIn('203.0.113.5', success['detail'])

    def test_ddns_classic_and_nochange(self):
        self.assertEqual(self.log('ddclient[123]: SUCCESS: updating foo.example.net: good: IP address set to 203.0.113.5')['category'], 'ddns_changed')
        self.assertIsNone(self.log('ddclient: Account id [cloudflare - ddclient] not modified', 'ddclient'))
        self.assertIsNone(self.log('ddclient: SUCCESS: foo.example.com: nochg 203.0.113.3'))
        self.assertEqual(self.log('ddclient: WARNING: no global IP address detected, check config if warning persists')['category'], 'ddns_error')

    def test_ddns_credentials_not_leaked(self):
        sample = '2026 Error ddclient Account 123 [cloudflare - native] authentication failed password=TOPSECRET https://example.com?token=TOPSECRET'
        parsed = self.log(sample, 'ddclient')
        self.assertEqual(parsed['category'], 'ddns_error')
        self.assertNotIn('TOPSECRET', str(parsed))
        self.assertNotIn('token=', str(parsed))

    def test_gateway_up_and_down(self):
        self.assertEqual(self.log('2026 host dpinger[234]: WAN_DHCP Alarm: loss 100%, delay 0ms')['category'], 'gateway_down')
        self.assertEqual(self.log('2026 host dpinger[234]: WAN_DHCP Clear: loss 0%, delay 17ms')['category'], 'gateway_up')
        self.assertEqual(self.log('dpinger[234]: WAN2 Alarm: latency 150ms')['category'], 'gateway_quality')

    def test_auth_event_and_privacy(self):
        sample='2026 host sshd[99]: Failed password for root from 203.0.113.12 port 51222 ssh2 password=SECRET'
        result=self.log(sample)
        self.assertEqual(result['category'], 'auth')
        self.assertIn('203.0.113.12',result['detail'])
        self.assertNotIn('SECRET',str(result))
        self.assertEqual(self.log('sshd[22]: Accepted publickey for root from 203.0.113.12 port 2')['category'], 'auth')
        self.assertIsNone(self.log('ssh-agent[3]: connection failed'))

    def test_crowdsec(self):
        self.assertEqual(self.log('2026 level=info msg="new decision" ip=203.0.113.12', 'crowdsec')['category'], 'crowdsec_decision')
        self.assertEqual(self.log('level=error msg="some dangerous URL and token"', 'crowdsec')['category'], 'crowdsec_error')
        self.assertIsNone(self.log('level=info msg="Starting agent"', 'crowdsec'))

    def test_vpn_and_dns(self):
        self.assertEqual(self.log('openvpn[4]: Initialization Sequence Completed')['category'], 'vpn_up')
        self.assertEqual(self.log('netbird[7]: peer disconnected')['category'], 'vpn_down')
        self.assertEqual(self.log('unbound[5]: upstream server 1.1.1.1 unreachable')['category'], 'dns')
        self.assertIsNone(self.log('dnsmasq[5]: query[A] bad.example.com from 192.168.1.2'))

    def test_dhcp(self):
        self.assertEqual(self.log('dnsmasq-dhcp[21]: DHCPACK(igc0) 192.168.1.10 aa:bb:cc:dd:ee:ff laptop')['category'], 'dhcp_lease')
        self.assertEqual(self.log('kea-dhcp4[5]: DHCP failed, subnet exhausted')['category'], 'dhcp')

    def test_backups_firmware_and_backend(self):
        self.assertEqual(self.log('pkg[23]: firmware update failed due to conflict')['category'], 'firmware')
        self.assertEqual(self.log('configd[99]: service reload failed with exception')['category'], 'backend')
        self.assertEqual(self.log('gdrive-backup: backup upload failed')['category'], 'backup')

    def test_filter_defaults_and_explicit_overrides(self):
        settings={'enabled':'1'}
        self.assertTrue(src.accepted(settings, 'ddns_changed'))
        self.assertTrue(src.accepted(settings, 'ddns_error'))
        self.assertFalse(src.accepted(settings, 'firewall'))
        self.assertFalse(src.accepted(settings, 'dhcp_lease'))
        self.assertFalse(src.accepted(settings, 'ids'))
        self.assertFalse(src.accepted(settings, 'wan_ip'))
        settings['notifyddnserrors']='0'
        self.assertFalse(src.accepted(settings, 'ddns_error'))
        settings['enabled']='0'
        self.assertFalse(src.accepted(settings, 'ddns_changed'))

    def test_fingerprint_repeat_reduction(self):
        state=watcher.load_state(Path('/missing'))
        self.assertTrue(watcher.enqueue(state,'Dynamic DNS','ddns_error','Provider rejected authentication',now=1000,cooldown=600))
        self.assertFalse(watcher.enqueue(state,'Dynamic DNS','ddns_error','Provider rejected authentication',now=1250,cooldown=600))
        self.assertTrue(watcher.enqueue(state,'Dynamic DNS','ddns_error','Provider rejected authentication',now=1700,cooldown=600))

    def test_firewall_aggregate_and_no_individual_packet(self):
        s={'enabled':'1','notifyfirewall':'1','maxenabled':'1'}
        state=watcher.load_state(Path('/missing'))
        with tempfile.TemporaryDirectory() as tmp:
            logfile=Path(tmp)/'latest.log'
            logfile.write_text('')
            with patch.object(src,'hint_for',return_value='firewall'):
                watcher.scan_log(s,state,log=logfile)
                with logfile.open('a') as fh:
                    for _ in range(15):
                        fh.write('filterlog[100]: 1,,,1234,igc1,match,block,in,4,0x0,... from 203.0.113.5\n')
                watcher.scan_log(s,state,log=logfile)
                self.assertEqual(len(state['queue']),0)
                self.assertFalse(watcher.emit_firewall_summary(s,state,now=state['firewall_aggregate']['since']+100))
                self.assertTrue(watcher.emit_firewall_summary(s,state,now=state['firewall_aggregate']['since']+301))
                self.assertEqual(state['queue'][0]['category'],'firewall')
                self.assertIn('15',state['queue'][0]['detail'])

    def test_dhcp_first_seen_once(self):
        state=watcher.load_state(Path('/missing'))
        self.assertTrue(watcher.new_dhcp_device(state,'aa:bb:cc:dd:ee:ff',1000))
        self.assertFalse(watcher.new_dhcp_device(state,'aa:bb:cc:dd:ee:ff',50000))
        self.assertTrue(watcher.new_dhcp_device(state,'aa:bb:cc:dd:ee:01',50000))

    def test_watch_log_integration_preserves_monit(self):
        s={'enabled':'1','notifyfailures':'1','notifyddnschanges':'1','maxenabled':'1'}
        with tempfile.TemporaryDirectory() as tmp:
            logfile=Path(tmp)/'latest.log';logfile.write_text('')
            state=watcher.load_state(Path(tmp)/'state.json')
            watcher.scan_log(s,state,log=logfile)
            with logfile.open('a') as fh:
                fh.write("monit[12]: 'RootFs' status failed (1)\n")
                fh.write('ddclient[12]: SUCCESS: updating foo.example.net: good: IP address set to 203.0.113.5\n')
            self.assertEqual(watcher.scan_log(s,state,log=logfile),2)
            self.assertEqual({x['category'] for x in state['queue']},{'failure','ddns_changed'})
            with patch.object(monit2max,'deliver') as send:
                self.assertEqual(watcher.flush_queue(s,state),2)
                self.assertEqual(send.call_count,2)

    def test_disabled_sources_not_discovered(self):
        settings={'enabled':'1'}
        dirs=src.source_directories(settings)
        self.assertNotIn('/var/log/filter', dirs)
        self.assertIn('/var/log/ddclient', dirs)
        self.assertIn('/var/log/crowdsec', dirs)
        settings.update({key:'0' for group in src.SOURCE_SETTINGS.values() for key in group})
        self.assertEqual(src.source_directories(settings),[])

    def test_suricata_json(self):
        record='{"event_type":"alert","src_ip":"203.0.113.7","alert":{"severity":1,"signature":"malicious"}}'
        self.assertEqual(self.log(record,'suricata')['category'],'ids')
        self.assertIsNone(self.log(record.replace('"severity":1','"severity":3'),'suricata'))

if __name__=='__main__':
    unittest.main()
