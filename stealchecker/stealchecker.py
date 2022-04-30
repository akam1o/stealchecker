#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import subprocess
import sys
import time


class StealChecker:

    def res_cmd(self, cmd):
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            shell=True).communicate()[0]

    def res_cmd_lfeed(self, cmd):
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            shell=True).stdout.readlines()

    def res_cmd_no_lfeed(self, cmd):
        return [str(x).rstrip("\n") for x in self.res_cmd_lfeed(cmd)]

    def get_domains(self):
        res = self.res_cmd_no_lfeed('virsh list')[2:-1]
        return [l.split()[1] for l in res if l]

    def get_dominfo(self, domain):
        res = self.res_cmd_no_lfeed('virsh dominfo %s' % domain)
        ret = {}
        for line in res:
            if line:
                ret[line.split()[0].split(':')[0]] = line.split()[1]
        return ret

    def get_dominfos(self, domains):
        return [self.get_dominfo(domain) for domain in domains]

    def get_infocpus(self, domain):
        res = self.res_cmd_no_lfeed('virsh qemu-monitor-command --hmp %s "info cpus"' % domain)
        return [l.split('thread_id=')[1].strip() for l in res if l]

    def get_schedstat(self, pid):
        res = self.res_cmd_no_lfeed('cat /proc/%s/schedstat' % pid)
        schedstat = res[0].split()
        ret = {'cpu_times': schedstat[0], 'cpu_runqueues': schedstat[1], 'cpu_contextswitch': schedstat[2]}
        return ret

    def get_schedstats(self, pids):
        ret = {'cpu_times': 0L, 'cpu_runqueues': 0L, 'cpu_contextswitch': 0L}
        for pid in pids:
            schedstat = self.get_schedstat(pid)
            ret['cpu_times'] += long(schedstat['cpu_times'])
            ret['cpu_runqueues'] += long(schedstat['cpu_runqueues'])
            ret['cpu_contextswitch'] += long(schedstat['cpu_contextswitch'])
        return ret

    def get_usage_dominfos(self):
        now = time.time()*1000000000
        lastusage = self.read_lastusage()
        domains = self.get_domains()
        dominfos = self.get_dominfos(domains)
        for dominfo in dominfos:
            pids = self.get_infocpus(dominfo['Name'])
            schedstat = self.get_schedstats(pids)
            dominfo['cpu_times'] = schedstat['cpu_times']
            dominfo['cpu_runqueues'] = schedstat['cpu_runqueues']
            dominfo['cpu_contextswitch'] = schedstat['cpu_contextswitch']
            dominfo['last_time'] = now
            try:
                dominfo['cpu_use'] = float(dominfo['cpu_times'] - lastusage[dominfo['Name']]['cpu_times']) / float(now - lastusage[dominfo['Name']]['last_time'])
                dominfo['cpu_steal'] = float(dominfo['cpu_runqueues'] - lastusage[dominfo['Name']]['cpu_runqueues']) / float(now - lastusage[dominfo['Name']]['last_time'])
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
        now = time.time()*1000000000
        ret = {}
        for dominfo in dominfos:
            try:
                ret[dominfo['Name']] = {'cpu_times': dominfo['cpu_times'],
                                        'cpu_runqueues': dominfo['cpu_runqueues'],
                                        'cpu_contextswitch': dominfo['cpu_contextswitch'],
                                        'cpu_use': dominfo['cpu_use'],
                                        'cpu_steal': dominfo['cpu_steal'],
                                        'UUID': dominfo['UUID'],
                                        'last_time': dominfo['last_time']}
            except:
                ret[dominfo['Name']] = {'cpu_times': 0L,
                                        'cpu_runqueues': 0L,
                                        'cpu_contextswitch': 0L,
                                        'last_time': now}
        try:
            with open('/tmp/last_steal.json', 'w') as f:
                f.write(json.dumps(ret))
            return True
        except:
            return False

    def stealcheck(self):
        lastusages = self.read_lastusage()
        dominfos = self.get_usage_dominfos()
        self.write_usage(dominfos)
        nowusages = self.read_lastusage()
        return nowusages

    def print_stealcheck(self, uuid=False):
        usages = self.stealcheck()
        if uuid:
            print("UUID\t\t\t\t%cpu_use\t%cpu_steal")
            for usage in usages:
                print("{:s}\t{:8.2%}\t{:8.2%}".format(usages[k]['UUID'], usages[k]['cpu_use'], usages[k]['cpu_steal']))
        else:
            print("domain\t\t\t%cpu_use\t%cpu_steal")
            for k in usages:
                print("{:s}\t{:8.2%}\t{:8.2%}".format(k, usages[k]['cpu_use'], usages[k]['cpu_steal']))


def main():
    StealChecker().print_stealcheck()


if __name__ == "__main__":
    main()