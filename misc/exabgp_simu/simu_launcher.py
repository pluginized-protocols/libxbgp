#! /usr/bin/env python3

# IF THE CODE IS RUN ON VIRTUAL MACHINE:
# PLEASE SET INTERFACE ON PROMISCUOUS MODE IF IT DOES NOT WORK !!!!

import argparse
import ipaddress
import os
import shlex
from contextlib import closing
from signal import SIGINT
from time import sleep

from subprocess import run, PIPE, Popen

from pyroute2 import NDB, NSPopen, netns

import requests
import json

FRROUTING = 1
BIRD = 2

SIMU_CONF = {
    "nb_run": 10,
    "ns_routers": [
        {
            'name': "BGP1",
            'address': '192.168.56.5/24',
            'start_script': ''
        },
        {
            'name': "BGP2",
            'address': '192.168.56.6/24',
            'start_script': ''
        }
    ],
    "bridge_info": {
        'name': 'br0',
        'address': '192.168.56.2/24',
        'physical_iface': 'eth1',
    },
    "test_router": {
        'type': FRROUTING,
        'interface': "eth1"
    }
}


class Counter:
    """
    Monotonic counter. Can be reset
    """

    def __init__(self, base=0):
        self._base = base
        self._counter = base

    def tick(self):
        curr = self._counter
        self._counter += 1
        return curr

    def reset(self):
        self._counter = self._base


def pre_start(base_dir, run_number):
    return {
        "method": "pre_start",
        "params": {
            'cmds': [
                'mkdir %s%d' % (base_dir, run_number)
            ]
        },
        "jsonrpc": "2.0",
        "id": counter.tick()
    }


def post_start(base_dir, run_number):
    return {
        "method": "post_start",
        "params": {
            'cmds': [
                "rm -rf %s%d" % (base_dir, run_number)
            ]
        },
        "jsonrpc": "2.0",
        "id": counter.tick()
    }


def launcher_frrouting(run_number, run_folder):
    return {
        "method": "launch_router",
        "params": {
            'launch_conf': {

                "pre_start": [
                    {
                        "path": "/home/thomas/Documents/GitHub/frr_ubpf/zebra/zebra",
                        "args": "-z %s/zebra.api -i %s/zebra.pid --vty_socket %s" % (
                            run_folder, run_folder, run_folder
                        )
                    },
                    {
                        'path': "/usr/bin/tcpdump",
                        'args': "-nn -i %s -w /tmp/my_trace_frrouting_%d.pcap" % (
                            SIMU_CONF['test_router']['interface'], run_number
                        )
                    }
                ],
                "proc": [
                    {
                        'path': "/home/thomas/Documents/GitHub/frr_ubpf/bgpd/bgpd",
                        'args': "-z %s/zebra.api -i %s/bgpd.pid --vty_socket %s" % (
                            run_folder, run_folder, run_folder
                        ),
                        'to_record': True,
                    }
                ],
            }
        },
        "jsonrpc": "2.0",
        "id": 0,
    }


def query_peer(peer_ip, which_implem, vtypath, vty_args):
    return {
        "method": "query_daemon",
        "params": {
            'type': which_implem,
            'peer': str(peer_ip),
            'vtypath': vtypath,
            'vty_args': vty_args
        },
        "jsonrpc": "2.0",
        "id": counter.tick(),
    }


def stop_simu():
    return {
        "method": "stop_router",
        "params": {},
        "jsonrpc": "2.0",
        "id": counter.tick()
    }


def post_request(url, data):
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(data), headers=headers).json()

    assert response['id'] == data['id']
    assert response['jsonrpc'] == "2.0"

    return response["result"]


def build_bridge(bridge_name, from_iface, prefix):
    with NDB() as ndb:

        # ugly ...
        try:
            ndb.interfaces[bridge_name]
            # if it reaches this code, then bridge already built
            raise ValueError("Bridge already built")
        except KeyError:
            pass

        # master physical interface IP must be flushed or started
        try:
            master_phys_ifs = ndb.interfaces[from_iface]
        except KeyError:
            raise ValueError("%s not found" % from_iface)

        if 'down' in master_phys_ifs['state']:
            master_phys_ifs.set('state', 'up').commit()
        else:
            if prefix in ndb.addresses:
                (ndb.interfaces[from_iface]
                 .del_ip(prefix)
                 .commit())

        # create new bridge interface with its dedicated IP address
        (ndb.interfaces
         .create(ifname=bridge_name, kind='bridge')
         .add_port(from_iface)
         .add_ip(prefix)
         .set('state', 'up')
         .commit())

        # bring master physical interface to the bridge
        (ndb.interfaces[from_iface]
         .set('master', ndb.interfaces[bridge_name]['index'])
         .commit())


def build_namespace(nsname, bridge, ip_pfx_ns):
    mirror = 'br-%s' % nsname
    ns_eth = '%s-eth0' % nsname

    net_ip = ip_pfx_ns.split('/')

    if len(net_ip) <= 1 or not net_ip[1].isdecimal():
        print("Malformed ip %s" % ip_pfx_ns)
        return

    with closing(NDB()) as ndb:
        # create namespace
        curr_ns = (ndb
                   .sources
                   .add(netns=nsname))

        # build pair of virtual ethernet interfaces
        (ndb
         .interfaces
         .create(ifname=ns_eth, peer=mirror, kind='veth')
         .commit())

        # link one veth to the namespace  and assign an IP address
        ns_iface = ndb.interfaces[ns_eth]
        ns_iface['net_ns_fd'] = nsname
        ns_iface.commit()

        # set the namespace interface UP
        idx_link_ns = curr_ns.nl.link_lookup(ifname=ns_eth)
        curr_ns.nl.addr('add', index=idx_link_ns, address=net_ip[0], mask=int(net_ip[1]))
        curr_ns.nl.link('set', index=idx_link_ns, state='up')

        # set the loopback namespace interface up
        idx_link_ns = curr_ns.nl.link_lookup(ifname='lo')
        curr_ns.nl.link('set', index=idx_link_ns, state='up')

        # include the mirror veth to the master bridge
        (ndb.interfaces[mirror]
         .set('state', 'up')
         .set('master', ndb.interfaces[bridge]['index'])
         .commit())


def setup_localconf(conf):
    # 1. setup bridge
    bridge = conf['bridge_info']
    build_bridge(bridge['name'], bridge['physical_iface'], bridge['address'])

    # 2. setup namespaces
    for curr_ns in conf['ns_routers']:
        build_namespace(curr_ns['name'], bridge['name'], curr_ns['address'])


def start_exabgp(ns_router_name, conf_exa):
    if ns_router_name not in netns.listnetns():
        print('namespace not started')
        return

    if ns_router_name in running_processes:
        print("Already running process for this NS")
        return

    proc = NSPopen(ns_router_name,
                   shlex.split(conf_exa['start_script']),
                   stdin=None,
                   stdout=None,
                   stderr=None)

    sleep(1)
    if proc.poll() is not None:
        print("Unable to launch exabgp router")
        return

    running_processes[ns_router_name] = proc


def stop_processes_from(namespace):
    if namespace not in running_processes:
        return

    proc = running_processes[namespace]
    proc.send_signal(SIGINT)

    sleep(1)
    if proc.poll() is None:
        proc.kill()
        sleep(0.5)

    proc.release()


def release_processes():
    for ns in running_processes.keys():
        stop_processes_from(ns)

    # wait before returning
    # be sure every child has been terminated
    sleep(1)


def are_you_alive(url):
    payload = {
        "method": "alive",
        "params": None,
        "jsonrpc": "2.0",
        "id": counter.tick()
    }

    res = post_request(url, payload)
    return res['code']


def manual_kill(nsname):
    iproc = Popen(shlex.split("ip netns pids %s" % nsname),
                  stdout=PIPE,
                  stdin=None,
                  stderr=None)

    iproc.wait()  # avoiding defunct process
    kill_proc = run(shlex.split("xargs kill -2"),
                    stdin=iproc.stdout)

    if kill_proc.returncode != 0:
        print("Error while killing processes")


def cleanup_namespace(nsname):
    if nsname in running_processes:
        stop_processes_from(nsname)
    else:
        manual_kill(nsname)

    netns.remove(nsname)


def cleanup(conf):
    for ns_router in conf['ns_routers']:
        cleanup_namespace(ns_router['name'])

    br_info = conf['bridge_info']

    # delete bridge and restore physical interface
    with closing(NDB()) as ndb:
        (ndb.interfaces[br_info['name']]
         .remove()
         .commit())

        (ndb.interfaces[br_info['physical_iface']]
         .add_ip(br_info['address'])
         .set('state', 'up')
         .commit())


def run_tests(url):
    pass


def main(args):
    # exit(0)

    try:
        host = ipaddress.ip_address(args.host)
        if host.version == 6:
            host = "[%s]" % str(host)
        else:
            host = str(host)
    except ValueError:
        host = args.host

    if args.port > 0xffff:
        exit(1)

    setup_localconf(SIMU_CONF)
    print("Host configured !")

    url = "http://%s:%d" % (host, args.port)

    print("Contacting remote at %s" % url)

    # check if the host is alive
    if not are_you_alive(url):
        print("Remote host is not alive")
        exit(1)

    run_tests(url)


if __name__ == "__main__":

    if os.getuid() != 0:
        print("The script must be run as root")
        exit(1)

    counter = Counter()
    running_processes = {}

    parser = argparse.ArgumentParser(description="Launch tests")
    parser.add_argument('-p', '--port', help="Port to reach out the test router",
                        type=int, default=4000)
    parser.add_argument('-r', '--host', help="IP address or the host name of the router",
                        type=str, default='localhost')

    main(parser.parse_args())
