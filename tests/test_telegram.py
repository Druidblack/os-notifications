"""Tests for Telegram transport, multi-provider routing and upgrade compatibility."""
from __future__ import annotations
import importlib.util
import io
import json
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
import urllib.error
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src/opnsense/scripts/OPNsense/Monit2Max'
sys.path.insert(0, str(SRC))
import monit2max as notify
import watcher


def config(**kwargs):
    return {'enabled': '1', 'provider': 'a161', 'token': 'max.secret',
            'recipienttype': 'user', 'recipientid': '12345',
            'maxenabled': '1', 'telegramenabled': '1',
            'telegramtoken': '123456:fake_Test_token', 'telegramchatid': '-10012345678',
            'telegramthreadid': '', 'title': 'OPNsense', **kwargs}


class Reply:
    def __init__(self, value=None, code=200):
        self.status = code
        self.payload = {'ok': True, 'result': {'message_id': 5}} if value is None else value
    def read(self, size=-1):
        return json.dumps(self.payload).encode('utf-8')
    def __enter__(self): return self
    def __exit__(self, *args): return False


class Opener:
    def __init__(self, value=None):
        self.requests = []
        self.value = value
    def open(self, request, timeout=12):
        self.requests.append(request)
        return Reply(self.value)


class TelegramTests(TestCase):
    def test_legacy_max_remains_enabled(self):
        self.assertEqual(notify.enabled_channels({'enabled': '1'}), ['max'])
        self.assertEqual(notify.enabled_channels({'enabled': '0'}), [])
        self.assertEqual(notify.enabled_channels(config(maxenabled='0')), ['telegram'])

    def test_telegram_chat_and_topic_in_request_body(self):
        opener = Opener()
        with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
            notify.send_telegram('123456:token_X', '-100200', 'hello', topic='777')
        request = opener.requests[0]
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.full_url, 'https://api.telegram.org/bot123456:token_X/sendMessage')
        self.assertEqual(json.loads(request.data), {'chat_id': '-100200', 'text': 'hello', 'message_thread_id': 777})
        self.assertIsNone(request.get_header('Authorization'))

    def test_telegram_public_channel_username(self):
        self.assertEqual(notify.validate_telegram_settings(config(telegramchatid='@public_test'))[1], '@public_test')
        with self.assertRaises(notify.NotifyError):
            notify.validate_telegram_settings(config(telegramchatid='chat;rm'))

    def test_telegram_invalid_secrets_and_topic(self):
        with self.assertRaises(notify.NotifyError):
            notify.validate_telegram_settings(config(telegramtoken='123\r\nInjected: X'))
        with self.assertRaises(notify.NotifyError):
            notify.validate_telegram_settings(config(telegramthreadid='-12'))
        with self.assertRaises(notify.NotifyError):
            notify.validate_telegram_settings(config(telegramchatid='0'))

    def test_telegram_api_rejects_false_success(self):
        opener = Opener({'ok': False, 'description': 'not found'})
        with patch.object(notify.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(notify.NotifyError, 'did not confirm'):
                notify.send_telegram('123:token_X', '12345', 'hello')

    def test_telegram_http_errors_redact_bot_token(self):
        secret = '12345:PRIVATE_SECRET'
        for status in (400, 401, 403, 429, 502):
            with self.subTest(status=status), patch.object(notify.urllib.request, 'build_opener') as op:
                op.return_value.open.side_effect = urllib.error.HTTPError('https://x.invalid', status, 'message', {}, None)
                with self.assertRaises(notify.NotifyError) as err:
                    notify.send_telegram(secret, '100', 'hi')
                self.assertNotIn(secret, str(err.exception))
                self.assertIn(str(status), str(err.exception))

    def test_telegram_no_redirects(self):
        self.assertIsNone(notify.NoRedirects().redirect_request(None, None, 302, 'redirect', {}, 'https://evil'))

    def test_both_delivery_one_fails_other_succeeds_no_duplicate(self):
        settings = config()
        state = {'queue': [], 'recent': {}}
        watcher.enqueue(state, 'MyHost', 'failure', 'CPU > 75%', now=1000, channels=notify.enabled_channels(settings))
        calls = []
        def send(_settings, channel, _message, **kwargs):
            calls.append(channel)
            if channel == 'max':
                raise notify.NotifyError('MAX offline')
        with patch.object(notify, 'deliver', side_effect=send):
            self.assertEqual(watcher.flush_queue(settings, state, now=1001), 1)
        self.assertEqual(calls, ['max', 'telegram'])
        self.assertEqual(state['queue'][0]['pending'], ['max'])
        self.assertIn('max', state['last_error_by'])
        with patch.object(notify, 'deliver') as send:
            self.assertEqual(watcher.flush_queue(settings, state, now=5000), 1)
            self.assertEqual(send.call_args.args[1], 'max')
        self.assertEqual(state['queue'], [])

    def test_disabled_channel_is_paused(self):
        settings = config(telegramenabled='0')
        state = {'queue': [], 'recent': {}}
        watcher.enqueue(state, 'router', 'failure', 'error', now=1000, channels=['max', 'telegram'])
        with patch.object(notify, 'deliver') as send:
            self.assertEqual(watcher.flush_queue(settings, state, now=1001), 1)
            self.assertEqual(send.call_count, 1)
        self.assertEqual(state['queue'][0]['pending'], ['telegram'])

    def test_queue_from_old_version_goes_only_to_max(self):
        settings = config()
        state = {'queue': [{'service':'router','category':'failure','detail':'failed',
                           'created':1000,'attempts':0,'due':1000}], 'recent': {}}
        with patch.object(notify, 'deliver') as send:
            self.assertEqual(watcher.flush_queue(settings, state, now=1001), 1)
            self.assertEqual(send.call_args.args[1], 'max')

    def test_pipeline_marks_complete_only_after_both(self):
        settings = config()
        state = {'queue': [], 'recent': {}, 'probes': {'a'*32: {'expected': ['max', 'telegram'], 'sent': False}}}
        watcher.enqueue(state, 'test', 'failure', 'status failed probe_id='+'a'*32,
                        now=1000, channels=['max','telegram'])
        def send(_settings, channel, _message, **kwargs):
            if channel == 'telegram':
                raise notify.NotifyError('Telegram offline')
        with patch.object(notify, 'deliver', side_effect=send):
            self.assertEqual(watcher.flush_queue(settings, state, now=1001), 1)
        self.assertFalse(state['probes']['a'*32]['sent'])
        self.assertIn('max', state['probes']['a'*32]['sent_by'])
        with patch.object(notify, 'deliver'):
            watcher.flush_queue(settings, state, now=10000)
        self.assertTrue(state['probes']['a'*32]['sent'])

    def test_form_tabs_and_template_upgrades(self):
        base = ROOT / 'src/opnsense'
        model = ET.parse(base / 'mvc/app/models/OPNsense/Monit2Max/Monit2Max.xml').getroot()
        for name in ('Enabled','MaxEnabled','Provider','Token','RecipientId','TelegramEnabled','TelegramToken','TelegramChatId'):
            self.assertIsNotNone(model.find('./items/general/' + name))
        for name in ('notifications','max','telegram'):
            fields = ET.parse(base / f'mvc/app/controllers/OPNsense/Monit2Max/forms/{name}.xml').getroot()
            self.assertGreater(len(fields), 0)
        template = (base / 'service/templates/OPNsense/Monit2Max/settings.conf').read_text()
        self.assertIn('MaxEnabled=',template)
        self.assertIn('TelegramChatId=',template)
        view=(base/'mvc/app/views/OPNsense/Monit2Max/index.volt').read_text()
        self.assertIn("'id': 'frm_Telegram'",view)
        self.assertIn('href="#notifications"',view)
        self.assertIn('href="#max"',view)
        self.assertIn('href="#telegram"',view)

if __name__ == '__main__': main()
