"""Gotify API, independent delivery, UI/OPNsense integration and upgrade contracts."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'src/opnsense'
sys.path.insert(0, str(BASE / 'scripts/OPNsense/Monit2Max'))
import monit2max as notify
import watcher


def settings(**kwargs):
    return {'enabled': '1', 'maxenabled': '1', 'telegramenabled': '1',
            'gotifyenabled': '1', 'gotifyserverurl': 'https://push.example.test/gotify',
            'gotifytoken': 'A_secret_tok', 'gotifypriority': '7',
            'title': 'Router alerts', **kwargs}


class Reply:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): return False


class Opener:
    def __init__(self, *, status=200, error=None):
        self.requests = []
        self.status = status
        self.error = error

    def open(self, request, timeout=12):
        self.requests.append(request)
        if self.error:
            raise self.error
        result = Reply()
        result.status = self.status
        return result


class GotifyTests(unittest.TestCase):
    def test_default_disabled_and_legacy_unchanged(self):
        self.assertEqual(notify.enabled_channels({'enabled': '1'}), ['max'])
        self.assertEqual(notify.enabled_channels(settings()), ['max', 'telegram', 'gotify'])
        self.assertEqual(notify.enabled_channels(settings(maxenabled='0', telegramenabled='0')), ['gotify'])
        self.assertEqual(notify.enabled_channels(settings(enabled='0')), [])

    def test_gotify_json_post_secret_header_and_reverse_proxy(self):
        opener = Opener(status=201)
        with mock.patch.object(notify.urllib.request, 'build_opener', return_value=opener):
            notify.send_gotify('https://push.example.test/gotify/', 'A_secret_tok',
                               'CPU > 90%', title='Router alerts', priority=7)
        req = opener.requests[0]
        self.assertEqual(req.full_url, 'https://push.example.test/gotify/message')
        self.assertEqual(req.get_method(), 'POST')
        self.assertEqual(req.get_header('X-gotify-key'), 'A_secret_tok')
        self.assertEqual(req.get_header('Content-type'), 'application/json')
        self.assertEqual(json.loads(req.data),
                         {'message': 'CPU > 90%', 'title': 'Router alerts', 'priority': 7})
        self.assertNotIn('A_secret_tok', req.full_url)
        self.assertNotIn('A_secret_tok', req.data.decode())

    def test_http_lan_server_allowed(self):
        base, token, priority = notify.validate_gotify_settings(settings(gotifyserverurl='http://192.168.1.5:8080'))
        self.assertEqual((base, token, priority), ('http://192.168.1.5:8080', 'A_secret_tok', 7))

    def test_invalid_urls_and_credentials_rejected_without_request(self):
        invalid = ('', 'push.example.test', 'file:///etc/passwd',
                   'https://user:pass@push.example.test',
                   'https://push.example.test/?token=secret',
                   'https://push.example.test/#fragment',
                   'https://push.example.test/message',
                   'https://push.example.test\r\nX-Evil: yes',
                   'http://push.example.test:bad', 'http:///nohost')
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(notify.NotifyError):
                    notify.validate_gotify_settings(settings(gotifyserverurl=url))
        for kwargs in ({'gotifytoken': ''}, {'gotifytoken': 'secret\r\nEvil: 1'},
                       {'gotifypriority': '-1'}, {'gotifypriority': '11'},
                       {'gotifypriority': '5;curl'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(notify.NotifyError):
                notify.validate_gotify_settings(settings(**kwargs))

    def test_http_error_explanation_never_exposes_token(self):
        for status in (400, 401, 403, 404, 429, 502):
            with self.subTest(status=status):
                opener = Opener(error=urllib.error.HTTPError('https://untrusted.invalid',status,
                                                              'server error with token A_secret_tok', {}, None))
                with mock.patch.object(notify.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(notify.NotifyError) as ctx:
                        notify.send_gotify('https://push.example.test', 'A_secret_tok', 'Hello')
                self.assertIn(str(status), str(ctx.exception))
                self.assertNotIn('A_secret_tok', str(ctx.exception))

    def test_redirects_are_disabled(self):
        opener = Opener()
        with mock.patch.object(notify.urllib.request, 'build_opener', return_value=opener) as factory:
            notify.send_gotify('https://push.example.test', 'A_secret_tok', 'Hello')
        self.assertTrue(any(isinstance(h, notify.NoRedirects) for h in factory.call_args.args))
        self.assertIsNone(notify.NoRedirects().redirect_request(None, None, 302, '', {}, 'http://evil.invalid'))

    def test_deliver_invokes_gotify_with_priority(self):
        with mock.patch.object(notify, 'send_gotify') as send:
            notify.deliver(settings(), 'gotify', 'Message', rate_limit=False)
        send.assert_called_once_with('https://push.example.test/gotify', 'A_secret_tok',
                                     'Message', title='Router alerts', priority=7, timeout=notify.TIMEOUT)

    def test_gotify_connection_test_does_not_require_global_enable(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'settings.conf'
            p.write_text('[general]\nEnabled=0\nGotifyEnabled=0\nGotifyServerUrl=https://push.example.test\n'
                         'GotifyToken=A_secret_tok\nGotifyPriority=5\nTitle=Router\n')
            with mock.patch.object(notify, 'send_gotify') as send:
                result = notify.run(config=p, test=True, channel='gotify', rate_limit=False)
        self.assertEqual(result['status'], 'ok')
        self.assertIn('Gotify', result['message'])
        send.assert_called_once()

    def test_three_routes_independent_retry(self):
        s = settings()
        state = {'queue':[], 'recent':{}}
        watcher.enqueue(state, 'OPNsense', 'failure', 'CPU > 90%', now=1000,
                        channels=notify.enabled_channels(s))
        calls=[]
        def send(_settings, channel, message, **kwargs):
            calls.append(channel)
            if channel == 'gotify':
                raise notify.NotifyError('Gotify unreachable')
        with mock.patch.object(notify, 'deliver', side_effect=send):
            self.assertEqual(watcher.flush_queue(s, state, now=1001), 2)
        self.assertEqual(calls, ['max', 'telegram', 'gotify'])
        self.assertEqual(state['queue'][0]['pending'], ['gotify'])
        with mock.patch.object(notify, 'deliver') as send_again:
            self.assertEqual(watcher.flush_queue(s, state, now=2000), 1)
        self.assertEqual(send_again.call_count, 1)
        self.assertEqual(send_again.call_args.args[1], 'gotify')
        self.assertEqual(state['queue'], [])

    def test_pipeline_completion_all_three_channels(self):
        key='b'*32
        state={'queue':[], 'recent':{},'probes':{key:{'expected':['max','telegram','gotify'], 'sent':False}}}
        watcher.enqueue(state, 'test', 'failure', 'failed probe_id='+key, now=1000,
                        channels=['max','telegram','gotify'])
        def deliver(_settings, channel, _message):
            if channel == 'gotify': raise notify.NotifyError('offline')
        with mock.patch.object(notify, 'deliver', side_effect=deliver):
            watcher.flush_queue(settings(), state, now=1001)
        self.assertFalse(state['probes'][key]['sent'])
        with mock.patch.object(notify, 'deliver'):
            watcher.flush_queue(settings(), state, now=2000)
        self.assertTrue(state['probes'][key]['sent'])

    def test_ui_model_menu_and_template_contract(self):
        root = ET.parse(BASE/'mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml').getroot()
        for field in ('GotifyEnabled','GotifyServerUrl','GotifyToken','GotifyPriority'):
            self.assertIsNotNone(root.find('./items/general/'+field))
        self.assertIsNone(root.find('./items/general/LogFile'))
        form = ET.parse(BASE/'mvc/app/controllers/OPNsense/Monit2Max/forms/gotify.xml').getroot()
        self.assertEqual(len(form.findall('field')), 4)
        notify_form = (BASE/'mvc/app/controllers/OPNsense/Monit2Max/forms/notifications.xml').read_text()
        self.assertNotIn('Event log path', notify_form)
        menu=ET.parse(BASE/'mvc/app/models/OPNsense/Monit2Max/Menu/Menu.xml').getroot()
        self.assertEqual(menu.find('./Services/SystemNotifications').attrib['url'], '/ui/monit2max')
        self.assertIsNone(menu.find('./Services/Monit/MAX'))
        view=(BASE/'mvc/app/views/OPNsense/Monit2Max/index.volt').read_text()
        for txt in ("'frm_Gotify'", 'href="#gotify"', 'test_gotify', 'testGotifyAct'):
            self.assertIn(txt, view)
        template=(BASE/'service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        self.assertIn('LogFile=auto', template)
        for key in ('GotifyEnabled','GotifyServerUrl','GotifyToken','GotifyPriority'):
            self.assertIn(key+'={{',template)
        actions=(BASE/'service/conf/actions.d/actions_monit2max.conf').read_text()
        self.assertIn('[gotifytest]',actions)
        self.assertIn('--test-gotify',actions)
        controller=(BASE/'mvc/app/controllers/OPNsense/Monit2Max/Api/ServiceController.php').read_text()
        self.assertIn('testGotifyAction',controller)

    def test_old_custom_logfile_setting_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)/'monit';d.mkdir()
            log=d/'latest.log';log.write_text('')
            with mock.patch.object(watcher,'AUTO_LOG_DIRS',(str(d),)),mock.patch.object(watcher,'AUTO_LOG_FILES',()):
                self.assertEqual(watcher.source_paths({'logfile':'/var/log/obsolete.log'}),[log])

if __name__ == '__main__':
    unittest.main()
