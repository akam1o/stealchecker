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

    def test_get_schedstat_rejects_non_numeric_pid(self):
        checker = stealchecker.StealChecker(
            conn=FakeConnection(),
            state_file='/tmp/unused-stealchecker-test.json',
        )

        self.assertEqual(checker.get_schedstat('1;touch'), stealchecker.empty_schedstat())

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

    def test_escape_prometheus_label(self):
        self.assertEqual(
            stealchecker.escape_prometheus_label('vm"name\\zone\n'),
            'vm\\"name\\\\zone\\n',
        )


if __name__ == '__main__':
    unittest.main()
