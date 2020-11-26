#!/usr/bin/env python3
import json
import os
import sys

from mako.template import Template
from argparse import ArgumentParser, FileType


class Config:
    def __init__(self, d):
        for k, v in d.items():
            if isinstance(v, dict):
                v = Config(v)
            self.__dict__[k] = v


default_env = {
    'daemon': {
        'ack': 'false',
        'daemonize': 'false',
    },
    'log': {
        'level': 'CRIT',
        'reactor': 'true',
        'processes': 'false',
        'network': 'true'
    },
    'api': {
        'cli': 'false',
    }
}


def main(args):
    template = Template(filename=args.template)
    env_template = Template(filename=args.env)

    session = json.loads(args.conf)

    exabgp_config = Config({
        "api_program": os.path.abspath(args.program),
        "local": {
            "ip_addr": session['local']['ip_addr'],
            "router_id": session['local']['router_id'],
            "asn": session['local']['asn'],
        },
        "peer": {
            "ip_addr": session['peer']['ip_addr'],
            "router_id": session['peer']['router_id'],
            "asn": session['peer']['asn'],
        }
    })

    if args.log:
        default_env['log']['destination'] = os.path.abspath(args.log)

    for tmpl, tmpl_args, suffix in ((template, exabgp_config, "exabgp.cfg"), (env_template, default_env, "exabgp.env")):
        with open(os.path.join(args.output, "%s%s" % (args.prefix, suffix)), 'w') as f:
            f.write(tmpl.render(conf=tmpl_args))


# {"local": {"ip_addr": "10.21.43.2","router_id": "10.21.43.2","asn": 65002},"peer": {"ip_addr": "10.21.43.4","router_id": "10.21.43.4","asn": 65004 }}

if __name__ == '__main__':
    parser = ArgumentParser()

    parser.add_argument('-P', '--program', type=str, help="Path to the ExaBGP program")
    parser.add_argument('-t', '--template', type=str, required=False, default="exabgp.exabgp",
                        help="Template to generate the ExaBGP conf")
    parser.add_argument('-e', '--env', type=str, required=False, default="exabgp.env.mako",
                        help="Template to generate the ExaBGP environment variable")
    parser.add_argument('-c', '--conf', type=str, required=True,
                        help="JSON formatted string containing the configuration of ExaBGP")
    parser.add_argument('-o', '--output', type=str, required=True,
                        help="Directory to put generated configuration files")
    parser.add_argument('-p', '--prefix', type=str, required=False, default="",
                        help="Prefix string to prepend to generated files")
    parser.add_argument('-l', '--log', type=str, required=False, default=None)

    main(parser.parse_args())
