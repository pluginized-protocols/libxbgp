#! /usr/bin/env python3
import argparse
import os
import random
import sys
from shutil import copy2
import json
from time import sleep

from mako.template import Template

from misc.exabgp_simu.generate_routes import parse_iptables_stream, build_bgp_route

myconf = {
    "route_to_announce": 100,  # testing purpose
    "file": None,  # to be filled by main
    "neighbors": [
        {
            "remote-as": 65002,
            "hold-time": 90,
            "local-address": "192.168.56.3",
            "router-id": "192.168.56.3",
            "peer-address": "192.168.56.2",
            "local-as": 65003,
            "name-process": "rte_65003_to_65002",
        },
        {
            "remote-as": 65002,
            "hold-time": 90,
            "local-address": "192.168.56.4",
            "router-id": "192.168.56.4",
            "peer-address": "192.168.56.2",
            "local-as": 65004,
            "name-process": "rte_65004_to_65002",
        }
    ]
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Build exabgp conf")
    parser.add_argument('-d', '--dir', help="Output directory", default=".", type=str)
    parser.add_argument('-f', '--file', help="File containing networks to announce",
                        type=argparse.FileType('r'), default=sys.stdin)
    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print("Error: path %s does not exists" % args.dir)
        exit(1)
    elif not os.access(args.dir, os.X_OK):
        print("Error: %s access refused" % args.dir)
        exit(1)

    ipnet = parse_iptables_stream(args.file)
    sample_ipnet = random.sample(ipnet,
                                 myconf['route_to_announce'] if len(ipnet) >= myconf['route_to_announce']
                                 else len(ipnet))

    for neighbor in myconf['neighbors']:
        output_args_announce = os.path.join(args.dir, "%s.json" % neighbor['name-process'])
        with open(output_args_announce, 'w') as j:
            json.dump(neighbor, j)

    routes = build_bgp_route(sample_ipnet)
    sampled_output = os.path.join(args.dir, "sampled_routes")
    exa_conf_output = os.path.join(args.dir, "exa_router.conf")

    with open(sampled_output, 'w') as r:
        for route in routes:
            r.write("%s\n" % str(route))
        r.flush()

    myconf['file'] = "sampled_routes"
    template = Template(filename="exa_conf.conf.mako")

    with open(exa_conf_output, 'w') as f:
        f.write(template.render(conf=myconf))

    copy2('announce_routes.py', args.dir)
