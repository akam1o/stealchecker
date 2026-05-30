import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


class FakeConnection:
    def __init__(self, domains=None):
        self.domains = domains or []

    def listAllDomains(self):
        return self.domains


class FakeDomain:
    def __init__(self, name='vm-1', uuid='uuid-1', active=True, active_error=None, name_error=None, uuid_error=None):
        self._name = name
        self._uuid = uuid
        self._active = active
        self._active_error = active_error
        self._name_error = name_error
        self._uuid_error = uuid_error

    def name(self):
        if self._name_error:
            raise self._name_error
        return self._name

    def UUIDString(self):
        if self._uuid_error:
            raise self._uuid_error
        return self._uuid

    def isActive(self):
        if self._active_error:
            raise self._active_error
        return self._active


sys.modules.setdefault(
    'libvirt',
    types.SimpleNamespace(open=lambda uri: FakeConnection()),
)

from stealchecker import stealchecker  # noqa: E402


class StealCheckerTest(unittest.TestCase):
    def test_get_infocpus_runs_virsh_without_shell(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='CPU #0: thread_id=123\n',
        )

        with mock.patch.object(stealchecker.subprocess, 'run', return_value=completed) as run:
            pids = checker.get_infocpus('vm;touch /tmp/pwned')

        self.assertEqual(pids, ['123'])
        self.assertEqual(
            run.call_args.args[0],
            ['virsh', 'qemu-monitor-command', '--hmp', 'vm;touch /tmp/pwned', 'info cpus'],
        )
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs['timeout'], checker.command_timeout)

    def test_get_infocpus_raises_on_virsh_failure(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout='',
            stderr='permission denied\n',
        )

        with mock.patch.object(stealchecker.subprocess, 'run', return_value=completed):
            with self.assertRaises(stealchecker.StealCheckerError):
                checker.get_infocpus('vm-1')

    def test_get_infocpus_raises_on_timeout(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
            command_timeout=1,
        )

        with mock.patch.object(
            stealchecker.subprocess,
            'run',
            side_effect=subprocess.TimeoutExpired(['virsh'], 1),
        ):
            with self.assertRaises(stealchecker.StealCheckerError):
                checker.get_infocpus('vm-1')

    def test_invalid_command_timeout_is_rejected(self):
        with self.assertRaises(stealchecker.StealCheckerError):
            stealchecker.StealChecker(
                conn=FakeConnection(),
                state_file='/tmp/unused-stealchecker-test.json',
                command_timeout='invalid',
            )

    def test_get_infocpus_raises_when_no_thread_ids_are_found(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='no cpus available\n',
        )

        with mock.patch.object(stealchecker.subprocess, 'run', return_value=completed):
            with self.assertRaises(stealchecker.StealCheckerError):
                checker.get_infocpus('vm-1')

    def test_get_schedstat_rejects_non_numeric_pid(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        with self.assertRaises(stealchecker.StealCheckerError):
            checker.get_schedstat('1;touch')

    def test_counter_reset_returns_first_sample_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / 'last_steal.json'
            with open(state_file, 'w') as f:
                json.dump({
                    'vm-1': {
                        'cpu_times': 200,
                        'cpu_runqueues': 50,
                        'cpu_contextswitch': 4,
                        'last_time': 1000000000,
                    }
                }, f)
            checker = stealchecker.StealChecker(
                conn=FakeConnection([FakeDomain()]),
                state_file=state_file,
            )

            with mock.patch.object(checker, 'get_infocpus', return_value=['123']):
                with mock.patch.object(checker, 'get_schedstats', return_value={
                    'cpu_times': 100,
                    'cpu_runqueues': 20,
                    'cpu_contextswitch': 3,
                }):
                    with mock.patch.object(stealchecker.time, 'time', return_value=2):
                        usage = checker.get_usage_dominfos()[0]

            self.assertEqual(usage['cpu_use'], 0.0)
            self.assertEqual(usage['cpu_steal'], 0.0)

    def test_uuid_change_returns_first_sample_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / 'last_steal.json'
            with open(state_file, 'w') as f:
                json.dump({
                    'vm-1': {
                        'UUID': 'old-uuid',
                        'cpu_times': 100,
                        'cpu_runqueues': 20,
                        'cpu_contextswitch': 4,
                        'last_time': 1000000000,
                    }
                }, f)
            checker = stealchecker.StealChecker(
                conn=FakeConnection([FakeDomain(uuid='new-uuid')]),
                state_file=state_file,
            )

            with mock.patch.object(checker, 'get_infocpus', return_value=['123']):
                with mock.patch.object(checker, 'get_schedstats', return_value={
                    'cpu_times': 200,
                    'cpu_runqueues': 60,
                    'cpu_contextswitch': 8,
                }):
                    with mock.patch.object(stealchecker.time, 'time', return_value=2):
                        usage = checker.get_usage_dominfos()[0]

            self.assertEqual(usage['cpu_use'], 0.0)
            self.assertEqual(usage['cpu_steal'], 0.0)

    def test_schedstat_disappearing_skips_domain(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection([FakeDomain()]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        with mock.patch.object(checker, 'get_infocpus', return_value=['123']):
            with mock.patch.object(checker, 'get_schedstat', side_effect=stealchecker.StealCheckerDomainGone()):
                self.assertEqual(checker.get_usage_dominfos(), [])

    def test_domain_that_stops_during_collection_is_skipped(self):
        domain = FakeDomain()
        checker = stealchecker.StealChecker(
            conn=FakeConnection([domain]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        def fail_after_domain_stops(domain_name):
            domain._active = False
            raise stealchecker.StealCheckerError('domain stopped')

        with mock.patch.object(checker, 'get_infocpus', side_effect=fail_after_domain_stops):
            self.assertEqual(checker.get_usage_dominfos(), [])

    def test_get_dominfos_skips_inactive_domains(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection([
                FakeDomain(name='active-vm', uuid='active-uuid'),
                FakeDomain(name='stopped-vm', uuid='stopped-uuid', active=False),
            ]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        self.assertEqual(checker.get_dominfos(), [{
            'Name': 'active-vm',
            'UUID': 'active-uuid',
        }])

    def test_get_dominfos_skips_domains_that_disappear(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection([
                FakeDomain(name='active-vm', uuid='active-uuid'),
                FakeDomain(name_error=Exception('domain not found')),
            ]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        self.assertEqual(checker.get_dominfos(), [{
            'Name': 'active-vm',
            'UUID': 'active-uuid',
        }])

    def test_get_dominfos_raises_on_unexpected_inspection_error(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection([
                FakeDomain(name_error=Exception('connection reset')),
            ]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        with self.assertRaises(stealchecker.StealCheckerError):
            checker.get_dominfos()

    def test_active_check_errors_do_not_hide_collection_failures(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection([
                FakeDomain(active_error=Exception('connection reset')),
            ]),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        with mock.patch.object(checker, 'get_dominfos', return_value=[{
            'Name': 'vm-1',
            'UUID': 'uuid-1',
        }]):
            checker.domains_by_name = {'vm-1': FakeDomain(active_error=Exception('connection reset'))}
            with mock.patch.object(checker, 'get_infocpus', side_effect=stealchecker.StealCheckerError('virsh failed')):
                with self.assertRaises(stealchecker.StealCheckerError):
                    checker.get_usage_dominfos()

    def test_domain_gone_active_check_skips_collection_failure(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        with mock.patch.object(checker, 'get_dominfos', return_value=[{
            'Name': 'vm-1',
            'UUID': 'uuid-1',
        }]):
            checker.domains_by_name = {'vm-1': FakeDomain(active_error=Exception('domain not found'))}
            with mock.patch.object(checker, 'get_infocpus', side_effect=stealchecker.StealCheckerError('virsh failed')):
                self.assertEqual(checker.get_usage_dominfos(), [])

    def test_exporter_uses_threading_http_server(self):
        cmd = stealchecker.CommandStealChecker()
        args = types.SimpleNamespace(port=9167)

        with mock.patch.object(cmd, 'require_root'):
            with mock.patch.object(cmd, 'checker', return_value=object()):
                with mock.patch.object(stealchecker, 'ThreadingHTTPServer') as server:
                    with mock.patch('builtins.print'):
                        cmd.command_exporter(args)

        server.assert_called_once_with(('', 9167), stealchecker.StealExporterHandler)
        server.return_value.serve_forever.assert_called_once()

    def test_write_usage_writes_to_configured_state_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / 'state' / 'last_steal.json'
            checker = stealchecker.StealChecker(conn=FakeConnection(), state_file=state_file)

            result = checker.write_usage([{
                'Name': 'vm-1',
                'UUID': 'uuid-1',
                'cpu_times': 100,
                'cpu_runqueues': 20,
                'cpu_contextswitch': 3,
                'cpu_use': 0.5,
                'cpu_steal': 0.1,
                'last_time': 12345,
            }])

            self.assertTrue(result)
            with open(state_file, 'r') as f:
                usage = json.load(f)
            self.assertEqual(usage['vm-1']['cpu_times'], 100)
            self.assertEqual(usage['vm-1']['UUID'], 'uuid-1')

    def test_write_usage_raises_on_state_file_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / 'last_steal.json'
            checker = stealchecker.StealChecker(conn=FakeConnection(), state_file=state_file)

            with mock.patch.object(stealchecker.tempfile, 'mkstemp', side_effect=OSError('no space')):
                with self.assertRaises(stealchecker.StealCheckerError):
                    checker.write_usage([])

    def test_escape_prometheus_label(self):
        self.assertEqual(
            stealchecker.escape_prometheus_label('vm"name\\zone\n'),
            'vm\\"name\\\\zone\\n',
        )


if __name__ == '__main__':
    unittest.main()
