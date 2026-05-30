#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import libvirt
from http.server import BaseHTTPRequestHandler, HTTPServer


DEFAULT_STATE_FILE = Path(os.environ.get(
    'STEALCHECKER_STATE_FILE',
    '/run/stealchecker/last_steal.json',
))


def empty_schedstat():
    return {'cpu_times': 0, 'cpu_runqueues': 0, 'cpu_contextswitch': 0}


def empty_usage():
    return {'cpu_use': 0.0, 'cpu_steal': 0.0}


def escape_prometheus_label(value):
    return str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')


class StealCheckerError(Exception):
    pass


class StealChecker:

    def __init__(self, conn=None, state_file=None):
        try:
            self.conn = conn if conn is not None else libvirt.open('qemu:///system')
        except Exception as e:
            raise StealCheckerError('failed to connect to libvirt: %s' % e) from e
        self.state_file = Path(state_file) if state_file is not None else DEFAULT_STATE_FILE

    def res_cmd_lfeed(self, cmd):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
        except OSError as e:
            raise StealCheckerError('failed to run %s: %s' % (' '.join(cmd), e)) from e
        if result.returncode != 0:
            error = result.stderr.strip() or 'exit status %s' % result.returncode
            raise StealCheckerError('failed to run %s: %s' % (' '.join(cmd), error))
        return result.stdout.splitlines()

    def ensure_state_dir(self):
        parent = self.state_file.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise StealCheckerError('failed to create state directory %s: %s' % (parent, e)) from e
        return parent

    def lock_path(self):
        return self.state_file.with_suffix(self.state_file.suffix + '.lock')

    def state_lock(self):
        parent = self.ensure_state_dir()
        lock_path = parent / self.lock_path().name
        lock_file = None
        try:
            lock_file = open(lock_path, 'w')
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        except OSError as e:
            if lock_file:
                lock_file.close()
            raise StealCheckerError('failed to lock state file %s: %s' % (lock_path, e)) from e
        return lock_file

    def get_dominfos(self):
        try:
            domains = self.conn.listAllDomains()
        except Exception as e:
            raise StealCheckerError('failed to list libvirt domains: %s' % e) from e
        ret = []
        for domain in domains:
            ret.append({'Name': domain.name(), 'UUID': domain.UUIDString()})
        return ret

    def get_infocpus(self, domain):
        res = self.res_cmd_lfeed(['virsh', 'qemu-monitor-command', '--hmp', domain, 'info cpus'])
        return [line.split('thread_id=')[1].strip() for line in res if line and 'thread_id=' in line]

    def get_schedstat(self, pid):
        if not str(pid).isdigit():
            raise StealCheckerError('invalid thread_id from virsh: %s' % pid)
        try:
            with open('/proc/%s/schedstat' % pid, 'r') as f:
                schedstat = f.readline().split()
        except OSError as e:
            raise StealCheckerError('failed to read schedstat for pid %s: %s' % (pid, e)) from e
        if len(schedstat) < 3:
            raise StealCheckerError('invalid schedstat for pid %s' % pid)
        try:
            ret = {'cpu_times': int(schedstat[0]), 'cpu_runqueues': int(schedstat[1]), 'cpu_contextswitch': int(schedstat[2])}
        except ValueError as e:
            raise StealCheckerError('invalid schedstat for pid %s' % pid) from e
        return ret

    def calculate_usage(self, dominfo, prev, now):
        period = float(now - prev['last_time'])
        if period <= 0:
            return empty_usage()
        if dominfo['cpu_times'] < prev['cpu_times'] or dominfo['cpu_runqueues'] < prev['cpu_runqueues']:
            return empty_usage()
        return {
            'cpu_use': float(dominfo['cpu_times'] - prev['cpu_times']) / period,
            'cpu_steal': float(dominfo['cpu_runqueues'] - prev['cpu_runqueues']) / period,
        }

    def get_schedstats(self, pids):
        ret = {'cpu_times': 0, 'cpu_runqueues': 0, 'cpu_contextswitch': 0}
        for pid in pids:
            schedstat = self.get_schedstat(pid)
            ret['cpu_times'] += int(schedstat['cpu_times'])
            ret['cpu_runqueues'] += int(schedstat['cpu_runqueues'])
            ret['cpu_contextswitch'] += int(schedstat['cpu_contextswitch'])
        return ret

    def get_usage_dominfos(self):
        now = time.time() * 1e9
        lastusage = self.read_lastusage()
        dominfos = self.get_dominfos()
        for dominfo in dominfos:
            pids = self.get_infocpus(dominfo['Name'])
            schedstat = self.get_schedstats(pids)
            dominfo['cpu_times'] = schedstat['cpu_times']
            dominfo['cpu_runqueues'] = schedstat['cpu_runqueues']
            dominfo['cpu_contextswitch'] = schedstat['cpu_contextswitch']
            dominfo['last_time'] = now
            try:
                prev = lastusage[dominfo['Name']]
                usage = self.calculate_usage(dominfo, prev, now)
                dominfo['cpu_use'] = usage['cpu_use']
                dominfo['cpu_steal'] = usage['cpu_steal']
            except (KeyError, TypeError, ValueError):
                usage = empty_usage()
                dominfo['cpu_use'] = usage['cpu_use']
                dominfo['cpu_steal'] = usage['cpu_steal']
        return dominfos

    def read_lastusage(self):
        try:
            with open(self.state_file, 'r') as f:
                res = json.load(f)
                return res if res else {}
        except (OSError, json.JSONDecodeError, TypeError):
            return {}

    def write_usage(self, dominfos):
        now = time.time() * 1e9
        ret = {}
        for dominfo in dominfos:
            try:
                ret[dominfo['Name']] = {
                    'cpu_times': dominfo['cpu_times'],
                    'cpu_runqueues': dominfo['cpu_runqueues'],
                    'cpu_contextswitch': dominfo['cpu_contextswitch'],
                    'cpu_use': dominfo['cpu_use'],
                    'cpu_steal': dominfo['cpu_steal'],
                    'UUID': dominfo['UUID'],
                    'last_time': dominfo['last_time']
                }
            except (KeyError, TypeError, ValueError):
                ret[dominfo['Name']] = {
                    'cpu_times': 0,
                    'cpu_runqueues': 0,
                    'cpu_contextswitch': 0,
                    'last_time': now
                }
        tmp_path = None
        try:
            parent = self.ensure_state_dir()
            fd, tmp_path = tempfile.mkstemp(prefix='.%s.' % self.state_file.name, dir=str(parent))
            with os.fdopen(fd, 'w') as f:
                json.dump(ret, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.state_file)
            return True
        except OSError as e:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise StealCheckerError('failed to write state file %s: %s' % (self.state_file, e)) from e

    def stealcheck(self):
        with self.state_lock():
            dominfos = self.get_usage_dominfos()
            if not self.write_usage(dominfos):
                raise StealCheckerError('failed to write state file %s' % self.state_file)
        usages = {}
        for dominfo in dominfos:
            usages[dominfo['Name']] = {
                'UUID': dominfo['UUID'],
                'cpu_use': dominfo['cpu_use'],
                'cpu_steal': dominfo['cpu_steal'],
                'cpu_times': dominfo['cpu_times'],
                'cpu_runqueues': dominfo['cpu_runqueues'],
                'cpu_contextswitch': dominfo['cpu_contextswitch'],
            }
        return usages

    def print_stealcheck(self, uuid=False, as_json=False):
        usages = self.stealcheck()
        if as_json:
            print(json.dumps(usages, indent=2))
            return

        if uuid:
            print("{:<40s}{:>16s}{:>16s}".format("Domain UUID", "%cpu_use", "%cpu_steal"))
            for k in usages:
                print("{:<40s}{:>16.2%}{:>16.2%}".format(usages[k]['UUID'], usages[k]['cpu_use'], usages[k]['cpu_steal']))
        else:
            print("{:<24s}{:>16s}{:>16s}".format("Domain Name", "%cpu_use", "%cpu_steal"))
            for k in usages:
                print("{:<24s}{:>16.2%}{:>16.2%}".format(k, usages[k]['cpu_use'], usages[k]['cpu_steal']))


class StealExporterHandler(BaseHTTPRequestHandler):
    checker = None

    def do_GET(self):
        if self.path == '/metrics':
            try:
                sc = self.checker if self.checker is not None else StealChecker()
                usages = sc.stealcheck()
            except StealCheckerError as e:
                output = 'stealchecker collection failed: %s\n' % e
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(output.encode())
                return

            lines = [
                '# HELP steal_cpu_use QEMU VM CPU use percent',
                '# TYPE steal_cpu_use gauge',
                '# HELP steal_cpu_steal QEMU VM CPU steal percent',
                '# TYPE steal_cpu_steal gauge',
            ]
            for name, info in usages.items():
                safe_name = escape_prometheus_label(name)
                safe_uuid = escape_prometheus_label(info['UUID'])
                lines.append('steal_cpu_use{name="%s",uuid="%s"} %f' % (safe_name, safe_uuid, info['cpu_use']))
                lines.append('steal_cpu_steal{name="%s",uuid="%s"} %f' % (safe_name, safe_uuid, info['cpu_steal']))
            output = '\n'.join(lines) + '\n'

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(output.encode())
        else:
            self.send_response(404)
            self.end_headers()


class CommandStealChecker():

    def __init__(self):
        self.sc = None

    def checker(self):
        if self.sc is None:
            self.sc = StealChecker()
        return self.sc

    def require_root(self):
        if os.geteuid() != 0:
            print("ERROR: You must be root", file=sys.stderr)
            raise SystemExit(1)

    def command(self):
        parser = argparse.ArgumentParser(
            prog='stealchecker',
            usage='%(prog)s check [options]',
            description='Check QEMU VM steal time')

        subparsers = parser.add_subparsers(dest='command')

        parser_check = subparsers.add_parser('check', help='Show per-VM steal/cpu')
        parser_check.add_argument('-u', '--uuid', action='store_true', help='print uuid')
        parser_check.add_argument('--json', action='store_true', help='output as json')
        parser_check.set_defaults(handler=self.command_check)

        parser_exporter = subparsers.add_parser('exporter', help='Run as prometheus exporter')
        parser_exporter.add_argument('--port', type=int, default=9167)
        parser_exporter.set_defaults(handler=self.command_exporter)

        args = parser.parse_args()
        if hasattr(args, 'handler'):
            args.handler(args)
        else:
            parser.print_help()

    def command_check(self, args):
        self.require_root()
        try:
            self.checker().print_stealcheck(uuid=args.uuid, as_json=args.json)
        except StealCheckerError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            raise SystemExit(1)

    def command_exporter(self, args):
        self.require_root()
        try:
            StealExporterHandler.checker = self.checker()
        except StealCheckerError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            raise SystemExit(1)
        server = HTTPServer(('', args.port), StealExporterHandler)
        print(f"Serving metrics on :{args.port}/metrics")
        server.serve_forever()


def main():
    cmd = CommandStealChecker()
    cmd.command()


if __name__ == "__main__":
    main()
