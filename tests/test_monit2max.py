"""Offline unit tests: python3 -m unittest discover -s tests -v."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import ssl
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'src/opnsense/scripts/OPNsense/Monit2Max/monit2max.py'
spec = importlib.util.spec_from_file_location('monit2max', MODULE)
notify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notify)


class FakeReply:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, status=200, error=None):
        self.requests = []
        self.status = status
        self.error = error

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return FakeReply(self.status)


class NotifyTests(unittest.TestCase):
    def create_config(self, path, *, enabled='1', token='test.secret', kind='user',
                      recipient='1234', provider='official'):
        provider_line = f'Provider={provider}\n' if provider is not None else ''
        path.write_text(f'[general]\nEnabled={enabled}\n{provider_line}Token={token}\n'
                        f'RecipientType={kind}\nRecipientId={recipient}\nTitle=My OPNsense\n',
                        encoding='utf-8')

    def execute(self, config, *, test=True, environ=None, status=200, error=None):
        opener = FakeOpener(status, error)
        with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
            result = notify.run(config=config, test=test, environ=environ, rate_limit=False)
        return result, opener.requests[0][0]

    def test_official_personal_message(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf)
            result, request = self.execute(conf)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.full_url, 'https://platform-api2.max.ru/messages?user_id=1234')
        self.assertEqual(request.get_header('Authorization'), 'test.secret')
        self.assertEqual(json.loads(request.data)['text'][:2], '🔔 ')
        self.assertIn('Test notification', request.data.decode())
        self.assertNotIn('test.secret', request.full_url)

    def test_existing_config_without_provider_uses_official(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, provider=None)
            _, request = self.execute(conf)
        self.assertTrue(request.full_url.startswith('https://platform-api2.max.ru/'))

    def test_official_group_recipient_and_event(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, kind='chat', recipient='-100200')
            env = {'MONIT_HOST': 'OPNsense', 'MONIT_SERVICE': 'VPN', 'MONIT_EVENT': 'Connection failed',
                   'MONIT_DESCRIPTION': 'Ping to remote peer failed', 'MONIT_DATE': 'Mon, 02 Nov 2026 22:00 +0300'}
            _, request = self.execute(conf, test=False, environ=env)
        self.assertIn('?chat_id=-100200', request.full_url)
        self.assertIn('Ping to remote peer failed', request.data.decode())
        self.assertIn('VPN', request.data.decode())

    def test_a161_personal_message(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, provider='a161', token='abc012-1234', recipient='56789')
            result, request = self.execute(conf, status=201)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(request.full_url, 'https://notify.a161.ru/messages?user_id=56789')
        self.assertEqual(request.get_header('Authorization'), 'abc012-1234')
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertIn('Test notification', json.loads(request.data)['text'])
        self.assertNotIn('abc012-1234', request.full_url)

    def test_a161_group_negative_id(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, provider='a161', kind='chat', recipient='-999')
            _, request = self.execute(conf)
        self.assertEqual(request.full_url, 'https://notify.a161.ru/messages?chat_id=-999')

    def test_a161_group_positive_id_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, provider='a161', kind='chat', recipient='123')
            with patch.object(notify.urllib.request, 'build_opener') as mocked:
                with self.assertRaisesRegex(notify.NotifyError, 'negative'):
                    notify.run(config=conf, test=True, rate_limit=False)
                mocked.assert_not_called()

    def test_disabled_does_not_send_regular_event(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, enabled='0')
            with patch.object(notify.urllib.request, 'build_opener') as mocked:
                with self.assertRaisesRegex(notify.NotifyError, 'disabled'):
                    notify.run(config=conf, test=False, rate_limit=False)
                mocked.assert_not_called()

    def test_disabled_still_allows_explicit_connection_test(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, enabled='0', provider='a161')
            result, request = self.execute(conf, test=True)
        self.assertEqual(result['status'], 'ok')
        self.assertIn('automatic notifications are disabled', result['message'])
        self.assertIn('notify.a161.ru/messages?', request.full_url)

    def test_invalid_provider_rejected(self):
        with self.assertRaisesRegex(notify.NotifyError, 'connection method'):
            notify.validate_settings({'provider': 'https://bad-site.example',
                                      'token': '123', 'recipientid': '123'})

    def test_invalid_id_and_token_fail_closed(self):
        for recipient in ['', '0', 'abc', '123;echo bad']:
            with self.assertRaises(notify.NotifyError):
                notify.validate_settings({'provider': 'official', 'token': 'abc',
                                          'recipienttype': 'chat', 'recipientid': recipient})
        with self.assertRaises(notify.NotifyError):
            notify.validate_settings({'provider': 'a161', 'token': 'evil\r\nheader',
                                      'recipienttype': 'user', 'recipientid': '2'})

    def test_api_error_does_not_expose_token_for_both_providers(self):
        err = urllib.error.HTTPError('https://service.invalid', 401, 'Forbidden', {}, None)
        for provider in ('official', 'a161'):
            with self.subTest(provider=provider):
                opener = FakeOpener(error=err)
                with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(notify.NotifyError) as caught:
                        notify.send_message('SECRET_TOKEN', 'user', '123', 'text', provider=provider)
                self.assertNotIn('SECRET_TOKEN', str(caught.exception))
                self.assertIn('401', str(caught.exception))

    def test_http_error_messages_are_actionable(self):
        for code, phrase in [(400, 'recipient ID'), (401, 'invalid or expired'),
                             (403, 'access forbidden'), (429, 'rate limit'),
                             (503, 'service temporarily unavailable')]:
            with self.subTest(code=code):
                opener = FakeOpener(error=urllib.error.HTTPError('https://example.invalid', code,
                                                                 'Error', {}, None))
                with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(notify.NotifyError) as caught:
                        notify.send_message('SECRET_TOKEN', 'user', '123', 'text', provider='a161')
                self.assertIn(phrase, str(caught.exception))
                self.assertNotIn('SECRET_TOKEN', str(caught.exception))

    def test_configd_action_preserves_error_json(self):
        actions = (ROOT / 'src/opnsense/service/conf/actions.d/actions_monit2max.conf').read_text()
        self.assertIn('type:script_output\nerrors:no', actions)
        view = (ROOT / 'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt').read_text()
        self.assertIn('saveAll(function ()', view)
        self.assertIn("'/api/monit2max/service/test'", view)
        controller = (ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/Api/ServiceController.php').read_text()
        self.assertIn("configdRun('monit2max test')", controller)

    def test_certificate_error_is_not_silenced(self):
        opener = FakeOpener(error=urllib.error.URLError(ssl.SSLCertVerificationError('no trust')))
        with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(notify.NotifyError, 'TLS certificate verification'):
                notify.send_message('secret', 'user', '123', 'hello', provider='a161')

    def test_no_api_redirects_with_credentials(self):
        handler = notify.NoRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, 'Moved', {}, 'https://evil.invalid'))

    def test_a161_rate_limit_is_one_second(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'settings.conf'
            self.create_config(conf, provider='a161')
            opener = FakeOpener()
            with patch.object(notify, 'enforce_rate_limit') as pacing, \
                 patch.object(notify.urllib.request, 'build_opener', return_value=opener):
                notify.run(config=conf, test=True)
                pacing.assert_called_once_with(min_interval=1.05)

    def test_message_bound_and_plain_text(self):
        message = notify.event_message('Title', {'MONIT_DESCRIPTION': 'Ж' * 5000})
        self.assertLessEqual(len(message), 4000)
        self.assertIn('Details:', message)

    def test_xml_schema_and_root_services_menu(self):
        files = list((ROOT / 'src/opnsense/mvc').rglob('*.xml'))
        self.assertEqual(len(files), 14)
        for xml_file in files:
            ET.parse(xml_file)
        menu = ROOT / 'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Menu/Menu.xml'
        root = ET.parse(menu).getroot()
        node = root.find('./Services/SystemNotifications')
        self.assertIsNotNone(node)
        self.assertEqual(node.attrib['url'], '/ui/monit2max')
        model = (ROOT / 'src/opnsense/mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml').read_text()
        template = (ROOT / 'src/opnsense/service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        self.assertIn('<Provider type="OptionField">', model)
        self.assertIn('Provider={{', template)


if __name__ == '__main__':
    unittest.main()
