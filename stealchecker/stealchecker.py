#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import os
import subprocess
import sys
import time
import libvirt
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading


class StealChecker:

    def __init__(self):
        self.conn = libvirt.open('qemu:///system')

    def res_cmd(self, cmd):
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            shell=True).communicate()[0]

    def res_cmd_lfeed(self, cmd):
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            shell=True, universal_newlines=True).stdout.readlines()

    def res_cmd_no_lfeed(self, cmd):
        return [str(x).rstrip("\n") for x in self.res_cmd_lfeed(cmd)]

    def get_dominfos(self):
        domains = self.conn.listAllDomains()
        ret = []
        for domain in domains:
            ret.append({'Name': domain.name(), 'UUID': domain.UUIDString()})
        return ret

    def get_infocpus(self, domain):
        res = self.res_cmd_no_lfeed('virsh qemu-monitor-command --hmp %s "info cpus"' % domain)
        return [l.split('thread_id=')[1].strip() for l in res if l and 'thread_id=' in l]

    def get_schedstat(self, pid):
        res = self.res_cmd_no_lfeed('cat /proc/%s/schedstat' % pid)
        if not res or len(res[0].split()) < 3:
            return {'cpu_times': 0, 'cpu_runqueues': 0, 'cpu_contextswitch': 0}
        schedstat = res[0].split()
        ret = {'cpu_times': int(schedstat[0]), 'cpu_runqueues': int(schedstat[1]), 'cpu_contextswitch': int(schedstat[2])}
        return ret

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
                period = float(now - prev['last_time'])
                dominfo['cpu_use'] = float(dominfo['cpu_times'] - prev['cpu_times']) / period if period else 0.0
                dominfo['cpu_steal'] = float(dominfo['cpu_runqueues'] - prev['cpu_runqueues']) / period if period else 0.0
            except:
                dominfo['cpu_use'] = 0.0
                dominfo['cpu_steal'] = 0.0
        return dominfos

    def read_lastusage(self):
        try:
            with open('/tmp/last_steal.json', 'r') as f:
                res = json.load(f)
                return res if res else {}
        except:
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
            except Exception:
                ret[dominfo['Name']] = {
                    'cpu_times': 0,
                    'cpu_runqueues': 0,
                    'cpu_contextswitch': 0,
                    'last_time': now
                }
        try:
            with open('/tmp/last_steal.json', 'w') as f:
                f.write(json.dumps(ret))
            return True
        except:
            return False

    def stealcheck(self):
        dominfos = self.get_usage_dominfos()
        self.write_usage(dominfos)
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
    def do_GET(self):
        if self.path == '/metrics':
            sc = StealChecker()
            usages = sc.stealcheck()

            lines = [
                '# HELP steal_cpu_use QEMU VM CPU use percent',
                '# TYPE steal_cpu_use gauge',
                '# HELP steal_cpu_steal QEMU VM CPU steal percent',
                '# TYPE steal_cpu_steal gauge',
            ]
            for name, info in usages.items():
                lines.append('steal_cpu_use{name="%s",uuid="%s"} %f' % (name, info['UUID'], info['cpu_use']))
                lines.append('steal_cpu_steal{name="%s",uuid="%s"} %f' % (name, info['UUID'], info['cpu_steal']))
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
        self.sc = StealChecker()

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
        self.sc.print_stealcheck(uuid=args.uuid, as_json=args.json)

    def command_exporter(self, args):
        server = HTTPServer(('', args.port), StealExporterHandler)
        print(f"Serving metrics on :{args.port}/metrics")
        server.serve_forever()


def main():
    if not os.getuid() == 0:
        print("ERROR: You must be root")
        exit(1)
    cmd = CommandStealChecker()
    cmd.command()

if __name__ == "__main__":
    main()
