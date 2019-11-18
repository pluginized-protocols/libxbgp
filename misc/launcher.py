#! /usr/bin/env python3

import os
import signal
import subprocess
import shlex
import sys
from os import EX_OK, EX_CONFIG, EX_USAGE
from time import sleep

__CONFIG = {
    "pre_start": [
        {
            "path": "/home/thomas/Documents/GitHub/frr_ubpf/zebra/zebra",
            "args": "-z /tmp/zebra.api -i /tmp/zebra.pid"
        }
    ],
    "proc": [
        {
            'path': "/home/thomas/Documents/GitHub/frr_ubpf/bgpd/bgpd",
            'args': "-z /tmp/zebra.api -i /tmp/bgpd.pid",
            'to_record': True,
        }
    ]
}

RUNNING_DAEMON = []


def sigint_handler(sig, frame):
    for daemon in RUNNING_DAEMON:
        daemon.send_signal(signal.SIGINT)

    exit(EX_OK)


def launch(conf):

    pid = -1

    for type_d in 'pre_start', 'proc':
        for daemon in conf[type_d]:
            proc = subprocess.Popen(
                shlex.split(' '.join((daemon['path'], daemon['args']))),
                stderr=sys.stderr,
                stdout=sys.stderr,
                stdin=None,
            )

            RUNNING_DAEMON.append(proc)
            if 'to_record' in daemon:
                if daemon['to_record']:
                    pid = proc.pid

    if pid == -1:
        print("no process to record!")
        for daemon in RUNNING_DAEMON:
            daemon.kill()
        exit(EX_CONFIG)

    sleep(1)

    perf = subprocess.Popen(shlex.split("perf record -p %d "
                                        "-ebranches,cycles,faults,instructions,cache-misses,cache-references "
                                        "-g" % pid))

    if perf.poll() is not None:
        for d in RUNNING_DAEMON:
            d.kill()
        exit(EX_CONFIG)

    RUNNING_DAEMON.append(perf)
    perf.wait()


if __name__ == '__main__':

    if os.getuid() != 0:
        print("Please run this script with root privileges")
        exit(EX_USAGE)

    signal.signal(signal.SIGINT, sigint_handler)
    launch(__CONFIG)
