#!/usr/bin/env python3

import sys
from time import sleep

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        while True:
            for route in f:
                sys.stdout.write("announce %s\n" % route.strip())
                sys.stdout.flush()
            sleep(180)  # announce time before readvertising the table
