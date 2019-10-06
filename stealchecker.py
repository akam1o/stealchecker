#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess


class StealChecker:

  def res_cmd(cmd):
    return subprocess.Popen(
      cmd, stdout=subprocess.PIPE,
      shell=True).communicate()[0]

  def res_cmd_lfeed(cmd):
    return subprocess.Popen(
      cmd, stdout=subprocess.PIPE,
      shell=True).stdout.readlines()

  def res_cmd_no_lfeed(cmd):
    return [str(x).rstrip("\n") for x in res_cmd_lfeed(cmd)]
