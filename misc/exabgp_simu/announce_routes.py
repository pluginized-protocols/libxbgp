#!/usr/bin/env python3

import sys
import json
from time import sleep, time


def target_neigh(data):
    neighbor_line = "neighbor %s" % data['peer-address']

    # this will be hardcoded....
    if 'local-as' in data:
        neighbor_line += " local-as %d" % data['local-as']

    if 'remote-as' in data:
        neighbor_line += " peer-as %d" % data['remote-as']

    if 'local-address' in data:
        neighbor_line += " local-ip %s" % data['local-address']

    if 'router-id' in data:
        neighbor_line += " router-id %s" % data['router-id']

    return neighbor_line


if __name__ == '__main__':

    with open(sys.argv[1]) as n:
        neighbor = json.load(n)

    target_neigh_line = target_neigh(neighbor)

    sleep(2)
    with open(sys.argv[2]) as f:
        for route in f:
            sys.stdout.write("%s announce %s\n" % (target_neigh_line, route.strip()))
            sys.stdout.flush()
    sleep(5)
    try:
        now = time()
        while True:
            line = sys.stdin.readline().strip()
            if not line or 'shutdown' in line:
                break
    except IOError:
        pass
