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
    def __init__(self, name='vm-1', uuid='uuid-1'):
        self._name = name
        self._uuid = uuid

    def name(self):
        return self._name

    def UUIDString(self):
        return self._uuid


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
