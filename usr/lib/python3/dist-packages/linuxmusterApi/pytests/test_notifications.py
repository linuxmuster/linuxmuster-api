import hashlib
import hmac
import json

import requests

from utils.notifications import notify_completion


def _base_config():
    return {'callback_url': 'https://example.test/hook', 'key': 'pubkey123', 'secret': 'topsecret', 'timeout': 5}


class TestNotifyCompletion:

    def test_noop_without_config(self, monkeypatch):
        calls = []
        monkeypatch.setattr('utils.notifications.requests.post', lambda *a, **k: calls.append((a, k)))

        notify_completion(
            {}, job_id='p1', command='sophomorix-check', school='default-school',
            caller='admin', status='success', exit_code=0,
            started_at='t0', completed_at='t1', log='ok',
        )

        assert calls == []

    def test_noop_without_callback_url(self, monkeypatch):
        calls = []
        monkeypatch.setattr('utils.notifications.requests.post', lambda *a, **k: calls.append((a, k)))

        notify_completion(
            {'secret': 'x'}, job_id='p1', command='sophomorix-check', school='default-school',
            caller='admin', status='success', exit_code=0,
            started_at='t0', completed_at='t1', log='ok',
        )

        assert calls == []

    def test_posts_expected_headers_and_body(self, monkeypatch):
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured['url'] = url
            captured['data'] = data
            captured['headers'] = headers
            captured['timeout'] = timeout

        monkeypatch.setattr('utils.notifications.requests.post', fake_post)
        monkeypatch.setattr('utils.notifications.time.time', lambda: 1739097600)
        monkeypatch.setattr('utils.notifications.VERSION', '7.4.7')

        notify_completion(
            _base_config(), job_id='default-school.abc123', command='sophomorix-add', school='default-school',
            caller='global-admin', status='success', exit_code=0,
            started_at='01 Jan 2026 00:00:00', completed_at='01 Jan 2026 00:05:00', log='did some stuff',
        )

        assert captured['url'] == 'https://example.test/hook'
        assert captured['timeout'] == 5

        headers = captured['headers']
        assert headers['Content-Type'] == 'application/json'
        assert headers['x-webhook-key'] == 'pubkey123'
        assert headers['x-webhook-timestamp'] == '1739097600'
        assert headers['User-Agent'] == 'linuxmuster-api/v7.4.7'
        assert headers['x-webhook-event-id'].startswith('evt-')

        body = json.loads(captured['data'])
        assert body == {
            'event': 'sophomorix.job.completed',
            'job_id': 'default-school.abc123',
            'command': 'sophomorix-add',
            'school': 'default-school',
            'caller': 'global-admin',
            'status': 'success',
            'exit_code': 0,
            'started_at': '01 Jan 2026 00:00:00',
            'completed_at': '01 Jan 2026 00:05:00',
            'log': 'did some stuff',
        }

    def test_signature_covers_timestamp_and_body(self, monkeypatch):
        captured = {}
        monkeypatch.setattr('utils.notifications.requests.post', lambda url, data=None, headers=None, timeout=None: captured.update(data=data, headers=headers))
        monkeypatch.setattr('utils.notifications.time.time', lambda: 1739097600)

        notify_completion(
            _base_config(), job_id='p1', command='sophomorix-check', school='default-school',
            caller='admin', status='success', exit_code=0,
            started_at='t0', completed_at='t1', log='',
        )

        expected_signature = hmac.new(
            b'topsecret', b'1739097600.' + captured['data'], hashlib.sha256
        ).hexdigest()
        assert captured['headers']['x-webhook-signature'] == f'sha256={expected_signature}'

        # Changing the timestamp alone must change the signature: it isn't
        # computed on the body alone, precisely to prevent replaying an
        # intercepted request with a stale-but-still-valid signature.
        monkeypatch.setattr('utils.notifications.time.time', lambda: 1739097601)
        notify_completion(
            _base_config(), job_id='p1', command='sophomorix-check', school='default-school',
            caller='admin', status='success', exit_code=0,
            started_at='t0', completed_at='t1', log='',
        )
        assert captured['headers']['x-webhook-signature'] != f'sha256={expected_signature}'

    def test_swallows_request_exception(self, monkeypatch):
        def raising_post(*a, **k):
            raise requests.exceptions.ConnectionError('boom')

        monkeypatch.setattr('utils.notifications.requests.post', raising_post)

        # Must not raise.
        notify_completion(
            _base_config(), job_id='p1', command='sophomorix-check', school='default-school',
            caller='admin', status='failed', exit_code=1,
            started_at='t0', completed_at='t1', log='',
        )

    def test_default_timeout_and_missing_key(self, monkeypatch):
        captured = {}
        monkeypatch.setattr('utils.notifications.requests.post', lambda *a, **k: captured.update(k))

        notify_completion(
            {'callback_url': 'https://example.test/hook'}, job_id='p1', command='sophomorix-check',
            school='default-school', caller='admin', status='success', exit_code=0,
            started_at='t0', completed_at='t1', log='',
        )

        assert captured['timeout'] == 5
        assert captured['headers']['x-webhook-key'] == ''
