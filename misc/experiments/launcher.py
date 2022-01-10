#! /usr/bin/env python3
import argparse
import os
import shlex
import signal
import subprocess
from os import EX_OK, EX_CONFIG, EX_USAGE
from pathlib import Path
from typing import Callable

import sys
import time
from time import sleep

from misc.experiments.daemons import TSHARK
from misc.experiments.global_utils import singleton, dry_run, dry_run_on
from misc.experiments.scenario import get_scenarios

try:
    from subprocess import DEVNULL  # Python 3.
except ImportError:
    DEVNULL = open(os.devnull, 'wb')


@singleton
class RunningDaemon(object):
    def __init__(self):
        self._daemons = list()

    def add_daemon(self, daemon, name):
        self._daemons.append((daemon, name))

    def kill_all(self):
        def find_tshark():
            for i in range(0, len(self._daemons)):
                if self._daemons[i][1] == TSHARK.NAME:
                    return i
            return -1

        def dkill(d):
            d.send_signal(signal.SIGINT)
            d.wait()

        # First kill tshark before any routing daemon
        # idx = find_tshark()
        if idx := find_tshark() >= 0:
            daemon, _ = self._daemons.pop(idx)
            dkill(daemon)

        while len(self._daemons) > 0:
            daemon, _ = self._daemons.pop()
            dkill(daemon)


def sigint_handler(sig, frame):
    RunningDaemon().kill_all()
    exit(EX_OK)


def main(args):
    if args.dry_run:
        dry_run_on()

    out_dir = Path(args.output_dir)

    if not out_dir.exists():
        out_dir.mkdir()
    elif not out_dir.is_dir():
        print("{directory} is not a directory !".format(directory=args.output_dir))
        exit(EX_CONFIG)

    # defining multiple scenarios is done in get_scenarios function
    scenario: Callable
    for scenario in get_scenarios():
        s: 'Scenario' = scenario(args.interface)
        s.launch(out_dir, RunningDaemon())


if __name__ == '__main__':
    if os.getuid() != 0:
        print("Please run this script with root privileges")
        exit(EX_USAGE)

    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", type=str, action='append',
                        required=True, dest='interface',
                        help='Interfaces on which tshark must capture packets')
    parser.add_argument("-o", "--output-dir",
                        required=True, dest='output_dir',
                        help='Output folder where experiments results will be stored')
    parser.add_argument("-n", "--nb-experiments", type=int,
                        default=10, dest='nb_experiments',
                        help='Number of runs to do for each scenario (default: 10)')
    parser.add_argument("-p", "--prefix-experiments",
                        required=True, dest='prefix_experiments',
                        help='Prefix string to insert at each file produced by the experiment')
    parser.add_argument("-t", "--timeout", help="Set the maximum time of the experiment",
                        required=True, dest='timeout', type=int)
    parser.add_argument("-w", "--wait", help="Amount of time to wait before restarting a new experiment",
                        required=True, dest='wait', type=int)
    parser.add_argument("-d", "--dry-run", dest='dry_run', action='store_true',
                        default=False, help="Do a dry run")

    main(parser.parse_args())
