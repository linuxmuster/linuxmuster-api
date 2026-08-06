import json
import os
import uuid

import pytest

from utils.sophomorix import parse_sophomorix_json, process_user


class FakeCompletedProcess:
    def __init__(self, returncode):
        self.returncode = returncode

    def communicate(self):
        return b'', b''


def _pid():
    return f"pytest.{uuid.uuid4().hex[:8]}"


class TestProcessUser:

    def test_writes_status_transitions_and_notifies_success(self, monkeypatch):
        pid = _pid()
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        def fake_popen(cmd, **kwargs):
            # The real script redirects its own output to logpath via shell
            # ('>>'); process_user() itself never writes it, only reads it
            # back afterwards.
            with open(logpath, 'w') as f:
                f.write('some sophomorix output\n')
            return FakeCompletedProcess(0)

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', fake_popen)

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        process_user(
            f'true >> {logpath};', pid,
            command='sophomorix-check', school='default-school', caller='admin',
            notifications_config={'callback_url': 'https://example.test'},
        )

        assert os.path.isfile(statuspath)
        with open(statuspath) as f:
            assert 'was completed at' in f.read()

        assert notified['job_id'] == pid
        assert notified['command'] == 'sophomorix-check'
        assert notified['school'] == 'default-school'
        assert notified['caller'] == 'admin'
        assert notified['status'] == 'success'
        assert notified['exit_code'] == 0
        assert notified['log'] == 'some sophomorix output\n'

        os.remove(logpath)
        os.remove(statuspath)

    def test_nonzero_exit_code_reported_as_failed(self, monkeypatch):
        pid = _pid()
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        def fake_popen(cmd, **kwargs):
            with open(logpath, 'w') as f:
                f.write('boom\n')
            return FakeCompletedProcess(1)

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', fake_popen)

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        process_user(f'false >> {logpath};', pid, notifications_config={'callback_url': 'https://example.test'})

        assert notified['status'] == 'failed'
        assert notified['exit_code'] == 1

        os.remove(logpath)
        os.remove(statuspath)

    def test_missing_log_file_reports_empty_log(self, monkeypatch):
        pid = _pid()
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', lambda cmd, **kwargs: FakeCompletedProcess(0))

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        process_user('noop', pid, notifications_config={'callback_url': 'https://example.test'})

        assert notified['log'] == ''

        os.remove(statuspath)

    def test_notify_completion_called_even_without_notifications_config(self, monkeypatch):
        # process_user() always calls notify_completion(); it's
        # notify_completion() itself that no-ops on an empty config — kept
        # that way so process_user() doesn't need its own separate guard.
        pid = _pid()
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', lambda cmd, **kwargs: FakeCompletedProcess(0))

        calls = []
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: calls.append(cfg))

        process_user('noop', pid)

        assert calls == [None]

        os.remove(statuspath)

    def test_check_output_is_parsed_and_update_kill_overlap_filtered(self, monkeypatch):
        pid = _pid()
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        raw_check_output = (
            "some diagnostic noise\n"
            "# JSON-begin\n"
            "{'CHECK_RESULT': {'UPDATE': {'user1': {'a': 1}, 'user2': {'a': 2}}, 'KILL': {'user2': {'a': 2}}}}\n"
            "# JSON-end\n"
        )

        def fake_popen(cmd, **kwargs):
            with open(logpath, 'w') as f:
                f.write(raw_check_output)
            return FakeCompletedProcess(0)

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', fake_popen)

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        process_user(f'sophomorix-check -jj >> {logpath} 2>&1;', pid, command='sophomorix-check')

        # user2 is in both UPDATE and KILL: only the KILL entry should remain.
        expected = {'CHECK_RESULT': {'UPDATE': {'user1': {'a': 1}}, 'KILL': {'user2': {'a': 2}}}}
        assert json.loads(notified['log']) == expected

        # The log file on disk is rewritten too, so polling sees the same
        # filtered result as the notification.
        with open(logpath) as f:
            assert json.loads(f.read()) == expected

        os.remove(logpath)
        os.remove(statuspath)

    def test_check_output_without_json_markers_falls_back_to_raw_log(self, monkeypatch):
        pid = _pid()
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        def fake_popen(cmd, **kwargs):
            with open(logpath, 'w') as f:
                f.write('sophomorix crashed before emitting anything usable\n')
            return FakeCompletedProcess(1)

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', fake_popen)

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        # Must not raise even though there's nothing to parse.
        process_user(f'sophomorix-check -jj >> {logpath} 2>&1;', pid, command='sophomorix-check')

        assert notified['log'] == 'sophomorix crashed before emitting anything usable\n'

        os.remove(logpath)
        os.remove(statuspath)

    def test_non_check_command_log_is_left_untouched(self, monkeypatch):
        # The parse/filter step is sophomorix-check-specific: a plain-text
        # sophomorix-add/update/kill log must never be run through it.
        pid = _pid()
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

        def fake_popen(cmd, **kwargs):
            with open(logpath, 'w') as f:
                f.write('Adding user jdupont... done.\n')
            return FakeCompletedProcess(0)

        monkeypatch.setattr('utils.sophomorix.subprocess.Popen', fake_popen)

        notified = {}
        monkeypatch.setattr('utils.sophomorix.notify_completion', lambda cfg, **kw: notified.update(kw))

        process_user(f'sophomorix-add >> {logpath};', pid, command='sophomorix-add')

        assert notified['log'] == 'Adding user jdupont... done.\n'

        os.remove(logpath)
        os.remove(statuspath)


class TestParseSophomorixJson:

    def test_extracts_dict_between_markers(self):
        raw = (
            "noise before\n"
            "# JSON-begin\n"
            "{'a': 1, 'b': 2}\n"
            "# JSON-end\n"
            "noise after\n"
        )
        assert parse_sophomorix_json(raw) == {'a': 1, 'b': 2}

    def test_only_first_block_is_used(self):
        raw = "# JSON-begin\n{'a': 1}\n# JSON-end\n# JSON-begin\n{'a': 2}\n# JSON-end\n"
        assert parse_sophomorix_json(raw) == {'a': 1}

    def test_missing_markers_raises_indexerror(self):
        with pytest.raises(IndexError):
            parse_sophomorix_json("no markers in this output at all")

    def test_empty_block_returns_empty_dict(self):
        assert parse_sophomorix_json("# JSON-begin\n# JSON-end\n") == {}

    def test_null_literal_is_quoted_before_eval(self):
        # sophomorix's dump uses bare `null`, not valid Python literal syntax.
        raw = "# JSON-begin\n{'a':null}\n# JSON-end\n"
        assert parse_sophomorix_json(raw) == {'a': 'null'}
