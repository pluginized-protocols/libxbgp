import json
import os
import shlex
import signal
import sys
import time

from argparse import ArgumentParser, FileType

from pyroute2 import IPRoute, netns, NetNS, NSPopen

__IFACE_MAX_LEN__ = 14
__TEMP_TOPO_DIR__ = '/tmp/topo_conf'


def new_iface(router):
    if 'iface' not in router:
        routers[router]['nb_iface'] += 1
        iface = "%s-eth%d" % (router, routers[router]['nb_iface'])
    else:
        iface = router['iface']

    if len(iface) >= __IFACE_MAX_LEN__:
        print("The interface name %s for router %s is too long. "
              "Consider to shorten the router name" % (iface, router))
        clean()
        return None

    if iface in routers[router['name']]['ifaces']:
        print("The interface name %s is already taken and "
              "configured on router %s" % (iface, router['name']))
        clean()
        return None

    routers[router['name']]['ifaces'].add(iface)

    return iface


def make_veth(r1, r2):
    r1_iface = new_iface(r1)
    r2_iface = new_iface(r2)

    if r1_iface is None or r2_iface is None:
        return False

    ip.link('add', ifname=r1_iface,
            kind='veth', peer=r2_iface)

    for ns_name, name_iface in ((r1, r1_iface), (r2, r2_iface)):
        ip.link('set', index=name_iface, net_ns_fd=ns_name)
        ns = routers[r1]['ns']
        idx = ns.link_lookup(ifname=name_iface)[0]
        ns.link('set', index=idx, state='up')

    return True


def make_ns(ns_name):
    try:
        new_netns = NetNS(ns_name, flags=os.O_CREAT | os.O_EXCL)
        idx = new_netns.link_lookup(ifname='lo')[0]
        new_netns.link('set', index=idx, state='up')
    except Exception as e:
        print("Cannot create namespace %s" % e)
        clean()
        return False

    routers[ns_name]['ns'] = new_netns
    return True


def add_router(router):
    r_name = router['name']
    if r_name in routers:
        print("Router already created")
        return

    if not make_ns(r_name):
        return

    routers[r_name] = {
        'nb_iface': 0,
        'ifaces': set()
    }


def build_routers(network_config):
    for pair in network_config['links']:
        if len(pair) != 2:
            clean()
            print("A link pair must exactly have 2 routers")
            return False

        r1 = pair[0]
        r2 = pair[1]

        if r1 not in routers:
            add_router(r1)
        if r2 not in routers:
            add_router(r2)

        if not make_veth(r1, r2):
            clean()
            print("Some errors has disrupted the network creation. "
                  "No network has been built.")
            return False
    return True


def set_ip_addresses(network_config):
    for router in routers.keys():
        if router not in network_config:
            print("[WARNING] No configuration provided for router %s. "
                  "You should manually configure every interface on this router."
                  % router)
        else:
            for interface in routers[router]['ifaces'].keys():
                if interface not in network_config[router]['ifaces']:
                    print("[WARNING] Interface %s don't have configuration for router %s. "
                          "You should manually configure IP for the %s interface."
                          % (interface, router, interface))
                else:
                    for ipver in routers[router]['ifaces'][interface].keys():
                        for ip_full in routers[router]['ifaces'][interface][ipver]:
                            ip_address = ip_full.split('/')[0]
                            mask = ip_full.split('/')[1]

                            ns = routers[router]['ns']
                            idx = ns.link_lookup(ifname=interface)[0]
                            ns.link('set', index=idx, state='up')
                            ns.addr('add', index=idx, address=ip_address, prefixlen=mask)


def start_daemons(network_conf):
    if 'folder_conf' not in network_conf:
        global_folder = os.path.dirname(os.path.realpath(__file__))
    else:
        global_folder = network_conf['folder_conf']

    if not os.path.isdir(global_folder):
        print("Unknown folder: %s.\nNetwork will not start." % global_folder)
        clean()
        return False

    for router in routers.keys():
        if router not in routers:
            print("[WARNING] Router conf is missing for %s." % router)
        elif 'folder' not in network_conf[router]:
            print("[WARNING] No folder for router %s. No daemons will be started")
        else:
            router_folder = os.path.join(global_folder, network_conf[router]['folder'])
            temp_link_folder = '%s/%s' % (__TEMP_TOPO_DIR__, router)
            os.symlink(router_folder, temp_link_folder)
            routers[router]['folder'] = temp_link_folder
            routers[router]['processes'] = []

            for command in routers[router]['daemons_start']:
                routers[router]['processes'].append(NSPopen(router, shlex.split(command)))

    return True


def post_build():
    for router in routers:
        router['ns'].close()


def clean(rset=None):
    def kill_all(process_router):
        for pid in processes[process_router]:
            os.kill(pid, signal.SIGINT)
            time.sleep(0.75)
            os.kill(pid, signal.SIGKILL)

    processes = netns.ns_pids()

    if rset:  # meaning we should clean the currently running network
        for r in rset:
            kill_all(r)

        for item in os.listdir(__TEMP_TOPO_DIR__):
            real_path = os.path.join(__TEMP_TOPO_DIR__, item)
            if os.path.islink(real_path):
                os.unlink(real_path)

        os.unlink(__TEMP_TOPO_DIR__)

    else:
        for router in routers.keys():
            ns = router['ns']
            kill_all(router)
            ns.close()
            ns.remove()


def main(args):
    config_load = json.load(args.topo)
    args.topo.close()

    if args.clean:
        router_set = set()
        for r1, r2 in config_load['link']:
            router_set.add(r1['name'])
            router_set.add(r2['name'])
        clean(router_set)
        return

    if os.path.exists(__TEMP_TOPO_DIR__):
        print("%s already exists. Is a network currently running ?" % __TEMP_TOPO_DIR__)
        return
    else:
        os.mkdir(__TEMP_TOPO_DIR__, 0o750)

    if not build_routers(config_load):
        return
    set_ip_addresses(config_load)
    start_daemons(config_load)


if __name__ == '__main__':
    ip = IPRoute()
    routers = {}
    parser = ArgumentParser(description="Topology manager")
    parser.add_argument("-t", "--topo", default=sys.stdin, type=FileType('w'),
                        help="Topology to reproduce in this machine")
    parser.add_argument('clean', required=False, action='store_true',
                        help="Clean everything related to the built network")

    main(parser.parse_args())
