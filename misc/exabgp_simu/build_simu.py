#! /usr/bin/env python3
import argparse
import os
import random
import sys
from contextlib import closing
from pathlib import Path
from shutil import copy2
import json

from mako.template import Template

from misc.exabgp_simu.generate_routes import parse_iptables_stream, build_bgp_route

MY_CONF = {
    "route_to_announce": 100,  # testing purpose
    "file": "???",  # :str to be filled by main
    "neighbors": [
        {
            "name": "BGP1",
            "remote-as": 65002,
            "hold-time": 90,
            "local-address": "192.168.56.3",
            "router-id": "192.168.56.3",
            "peer-address": "192.168.56.2",
            "local-as": 65003,
            "name-process": "rte_65003_to_65002",
        },
        {
            "name": "BGP2",
            "remote-as": 65002,
            "hold-time": 90,
            "local-address": "192.168.56.4",
            "router-id": "192.168.56.4",
            "peer-address": "192.168.56.2",
            "local-as": 65004,
            "name-process": "rte_65004_to_65002",
        }
    ],
}


def check_dir(dir_path: str):
    the_path = Path(dir_path)
    if the_path.exists():
        if the_path.is_dir():
            return
        raise NotADirectoryError

    the_path.mkdir(parents=True, exist_ok=True)


def build_exaconf_router(conf_path: str, templt, split=False):
    """
    Build the configuration to start ExaBGP daemon
    :param split: If split is false, one exaconf file is created (ExaBGP is in charge to
    simulate multiple routers). If true, create one ExaBGP conf for each router.
    The configuration is saved in confpath/neighbor['name']
    :param conf_path: directory to save configuration files
    :param templt: Mako template
    :return: void
    """

    check_dir(conf_path)
    if split:
        for neighbor_info in MY_CONF['neighbors']:
            custom_conf = MY_CONF.copy()
            custom_conf['neighbors'] = [neighbor_info]

            custom_path_conf = os.path.join(conf_path, neighbor_info['name'])
            check_dir(custom_path_conf)
            custom_path_conf = os.path.join(custom_path_conf, "%s_exa_conf.conf" % neighbor_info['name'])

            with closing(open(custom_path_conf, 'w')) as file:
                file.write(templt.render(conf=custom_conf))
    else:
        custom_path_conf = os.path.join(conf_path, "exa_router.conf")

        with closing(open(custom_path_conf, 'w')) as file:
            file.write(templt.render(conf=MY_CONF))


def build_neighbor_json(conf_path: str, split: bool = False):
    """

    :param conf_path:
    :param split:
    :return:
    """

    for curr_neighbor in MY_CONF['neighbors']:
        if split:
            info_neigh_path = os.path.join(conf_path, curr_neighbor['name'])
            check_dir(info_neigh_path)
        else:
            info_neigh_path = conf_path

        info_neigh_path = os.path.join(info_neigh_path, "%s.json" % curr_neighbor['name-process'])

        with closing(open(info_neigh_path, 'w')) as json_file:
            json.dump(curr_neighbor, json_file)


def build_sampled_route(conf_path: str, pfx_routes, split: bool = False):
    MY_CONF['file'] = "sampled_route"
    stream = '\n'.join([str(pfx) for pfx in pfx_routes])

    if split:
        for curr_neighbor in MY_CONF['neighbors']:
            my_join = os.path.join(conf_path, curr_neighbor['name'])
            check_dir(my_join)
            with closing(open(os.path.join(my_join, MY_CONF['file']), 'w')) as f:
                f.write(stream)
    else:
        with closing(open(os.path.join(conf_path, MY_CONF['file']), 'w')) as f:
            f.write(stream)


def copy_helper_daemon(conf_dir, split=False):
    if split:
        for curr_neighbor in MY_CONF['neighbors']:
            copy2('announce_routes.py', os.path.join(conf_dir, curr_neighbor['name']))
    else:
        copy2('announce_routes.py', conf_dir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Build exabgp conf")
    parser.add_argument('-d', '--dir', help="Output directory", default=".", type=str)
    parser.add_argument('-f', '--file', help="File containing networks to announce",
                        type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument('-s', '--split', help="Whether or not the test is split into multiple routers",
                        action='store_true')

    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print("Error: path \"%s\" does not exist" % args.dir)
        exit(1)
    elif not os.access(args.dir, os.X_OK):
        print("Error: \"%s\" access refused" % args.dir)
        exit(1)

    ipnet = parse_iptables_stream(args.file)
    sample_ipnet = random.sample(ipnet,
                                 MY_CONF['route_to_announce'] if len(ipnet) >= MY_CONF['route_to_announce']
                                 else len(ipnet))

    routes = build_bgp_route(sample_ipnet)

    build_neighbor_json(args.dir, split=args.split)
    build_sampled_route(args.dir, routes, split=args.split)

    template = Template(filename="exa_conf.conf.mako")
    build_exaconf_router(args.dir, template, split=args.split)

    copy_helper_daemon(args.dir, split=args.split)
