#! /usr/bin/env python3
import json
import os
import signal
import subprocess
import shlex
import sys
from contextlib import closing
from os import EX_OK, EX_CONFIG, EX_USAGE
from pathlib import Path
from time import sleep

__CONFIG = {
    "pre_start": [
        {
            "path": "/home/thomas/Documents/GitHub/frr_ubpf/zebra/zebra",
            "args": "-z /tmp/zebra.api -i /tmp/zebra.pid"
        },
        {
            'path': "/usr/bin/tcpdump",
            'args': "-nn -i eth1 -w /tmp/my_trace_bgp.pcap"
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


def err_log(msg: str):
    sys.stderr.write("[FAILED] %s\n" % msg)
    sys.stderr.flush()


def info_log(msg: str):
    sys.stderr.write("[INFO] %s\n" % msg)
    sys.stderr.flush()


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
        err_log("No process to record!")
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
    info_log("OK")
    perf.wait()


if __name__ == '__main__':
    if os.getuid() != 0:
        err_log("Please run this script with root privileges")
        exit(EX_USAGE)

    signal.signal(signal.SIGINT, sigint_handler)
    if len(sys.argv) == 1:
        launch(__CONFIG)
    elif len(sys.argv) == 2:

        the_path = Path(sys.argv[1])
        if the_path.exists():
            with closing(open(sys.argv[1], 'r')) as f:
                my_conf = json.load(f)
        else:
            my_conf = json.loads(sys.argv[1])

        launch(my_conf)
    else:
        err_log("Wrong number of arguments")
        exit(1)
