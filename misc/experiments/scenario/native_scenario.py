from __future__ import annotations
from ipaddress import ip_address
from typing import Union

from misc.experiments.config_generator import FRR, BIRD, Config, EXABGP, AddressFamilyConfig, DirIn, DirOut
from misc.experiments.example_config_generator import gen_dut_conf
from misc.experiments.post_script import PreScript, PostScript
from misc.experiments.scenario.scenario_utils import new_scenario


def pre_script_ifdown(file_path, iface):
    sh_script = """#!/usr/bin/env bash
    
    if [[ $EUID -ne 0 ]]; then
      echo "This script must be run as root" 
      exit 1
    fi
    
    ssh -i /home/thomas/id_rsa root@10.0.0.4 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "ip link set dev {iface} down"
    
    """.format(iface=iface)

    with open(file_path, 'w') as f:
        f.write(sh_script)

    return PreScript(f"bash {file_path}", 0)


def post_script_ifup(file_path, iface):
    sh_script = """#!/usr/bin/env bash
    
    if [[ $EUID -ne 0 ]]; then
      echo "This script must be run as root" 
      exit 1
    fi
    
    ssh -i /home/thomas/id_rsa root@10.0.0.4 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "ip link set dev {iface} up"
    
    """.format(iface=iface)

    with open(file_path, 'w') as f:
        f.write(sh_script)

    # post sleep 60s after re-enabling the remote interface up
    # to let the BGP daemon establishes the connection with
    # the remote peer
    return PostScript(f'bash "{file_path}"', 80, post_sleep=60)


def strsuite2obj(str_suite: str):
    if str_suite == 'frr':
        return FRR()
    elif str_suite == 'bird':
        return BIRD()
    raise Exception(f'"{str_suite}" is not a valid BGP implementation')


def config_dut_generic(config_path, dut_suite: str, dut_conf: dict[str, Union[int, str, list[str]]]):
    con = Config(config_path)

    monit = con.new_node("monitor", suite=EXABGP())
    dut = con.new_node("dut", suite=strsuite2obj(dut_suite))
    injecter1 = con.new_node("injecter1", suite=FRR())
    injecter2 = con.new_node("injecter2", suite=FRR())

    bgp_monit = monit.add_bgp_config()
    bgp_dut = dut.add_bgp_config()
    bgp_injecter1 = injecter1.add_bgp_config()
    bgp_injecter2 = injecter2.add_bgp_config()

    bgp_monit.set_as(65022)
    bgp_dut.set_as(dut_conf['as'])
    bgp_injecter1.set_as(65020)
    bgp_injecter2.set_as(65020)

    monit.set_router_id(ip_address("42.0.1.2"))
    dut.set_router_id(ip_address("42.0.2.1"))
    injecter1.set_router_id(ip_address("42.0.2.2"))
    injecter2.set_router_id(ip_address("42.4.0.1"))

    bgp_monit.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_monit.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)
    dut_ipv4_unicast = bgp_dut.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    dut_ipv6_unicast = bgp_dut.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter1.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter1.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter2.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter2.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)

    n1_neigh_conf, n2_neigh_conf = con.make_link(node1=monit, node2=dut,
                                                 ip_node1=ip_address(dut_conf["ip_monitor"]),
                                                 ip_node2=ip_address(dut_conf["ip_dut_monitor"]))

    dut_neigh_inject1_conf, inject_neigh_dut_conf = \
        con.make_link(node1=dut, node2=injecter1,
                      ip_node1=ip_address(dut_conf["ip_dut_injecter1"]),
                      ip_node2=ip_address(dut_conf["ip_injecter1"]))

    dut_neigh_inject2_conf, inject2_neigh_dut_conf = \
        con.make_link(node1=dut, node2=injecter2,
                      ip_node1=ip_address(dut_conf["ip_dut_injecter2"]),
                      ip_node2=ip_address(dut_conf["ip_injecter2"]))

    n1_neigh_conf.set_holdtime(240)
    n2_neigh_conf.set_holdtime(240)
    n2_neigh_conf.set_description("Send to monitor")
    dut_neigh_inject1_conf.set_description("Receive from injector")
    dut_neigh_inject2_conf.set_description("Receive from injector2")

    n1_neigh_conf.add_process("injecter", "python3 /the/file ;")

    block_all = con.new_acl_filter('route_block', 'ipv4')
    perm_all = con.new_acl_filter('route_all', 'ipv4')
    block_all6 = con.new_acl_filter('route_block6', 'ipv6')
    perm_all6 = con.new_acl_filter('route_all6', 'ipv6')

    block_all.deny_all()
    perm_all.permit_all()
    block_all6.deny_all()
    perm_all6.permit_all()

    n2_neigh_conf.set_filter_acl(block_all, DirIn())
    n2_neigh_conf.set_filter_acl(perm_all, DirOut())
    n2_neigh_conf.set_filter_acl(block_all6, DirIn())
    n2_neigh_conf.set_filter_acl(perm_all6, DirOut())

    dut_neigh_inject1_conf.set_filter_acl(perm_all, DirIn())
    dut_neigh_inject1_conf.set_filter_acl(block_all, DirOut())
    dut_neigh_inject1_conf.set_filter_acl(perm_all6, DirIn())
    dut_neigh_inject1_conf.set_filter_acl(block_all6, DirOut())

    dut_neigh_inject2_conf.set_filter_acl(perm_all, DirIn())
    dut_neigh_inject2_conf.set_filter_acl(block_all, DirOut())
    dut_neigh_inject2_conf.set_filter_acl(perm_all6, DirIn())
    dut_neigh_inject2_conf.set_filter_acl(block_all6, DirOut())

    con.write_conf()

    return dut.output_path, dut.extra_config


def config_dut_2peers(config_path, suite_str, scenario):
    if scenario is not None:
        scenario.add_metadata('ip_dut_injecter', '42.0.2.1')
        scenario.add_metadata('ip_dut_monitor', '42.0.1.1')
        scenario.add_metadata('ip_injecter', '42.0.2.2')
        scenario.add_metadata('ip_monitor', '42.0.1.2')

    return config_dut_generic(config_path, suite_str, {
        'as': 65021,
        'ip_dut_injecter1': "42.0.2.1",
        'ip_dut_injecter2': "42.4.0.2",
        'ip_dut_monitor': "42.0.1.1",
        'ip_injecter1': "42.0.2.2",
        'ip_injecter2': "42.4.0.1",
        'ip_monitor': "42.0.1.2"
    }, )


def scenario_frr_native(interfaces):
    return new_scenario(interfaces, routing_suite='frr',
                        bin_path="/home/thomas/frr_native/sbin",
                        scenario_name='FRR Native', confdir="/tmp/launch/confdir",
                        dut_conf_generator=gen_dut_conf)


def scenario_bird_native(interfaces):
    return new_scenario(interfaces, routing_suite='bird',
                        bin_path="/home/thomas/bird_native/sbin",
                        scenario_name='BIRD Native', confdir="/tmp/launch/confdir",
                        dut_conf_generator=gen_dut_conf)


def scenario_frr_native_2peers(interfaces):
    post_script = post_script_ifup('/tmp/launch/ifup.sh', 'enp4s0f1')
    pre_script = pre_script_ifdown('/tmp/launch/ifdown.sh', 'enp4s0f1')

    return new_scenario(interfaces, routing_suite='frr',
                        bin_path="/home/thomas/frr_native/sbin",
                        scenario_name='frr_native_2peers', confdir="/tmp/launch/confdir",
                        dut_conf_generator=config_dut_2peers, post_script=post_script, pre_script=pre_script)


def scenario_bird_native_2peers(interfaces):
    post_script = post_script_ifup('/tmp/launch/ifup.sh', 'enp4s0f1')
    pre_script = pre_script_ifdown('/tmp/launch/ifdown.sh', 'enp4s0f1')
    return new_scenario(interfaces, routing_suite='bird',
                        bin_path="/home/thomas/bird_native/sbin",
                        scenario_name='bird_native_2peers', confdir="/tmp/launch/confdir",
                        dut_conf_generator=config_dut_2peers, post_script=post_script, pre_script=pre_script)
