from __future__ import annotations
from ipaddress import ip_address
from typing import Union

from misc.experiments.config_generator import Config, EXABGP, FRR, IPV6_UNICAST, IPV4_UNICAST, DirIn, DirOut, BIRD
from misc.experiments.global_utils import dry_run
from misc.experiments.plugin_conf import Code, Plugin, PluginManifest
from misc.experiments.post_script import PostScript, PreScript
from misc.experiments.scenario.scenario_utils import new_scenario


def vrf_manifest(memcheck):
    strict_check = False if dry_run() else True

    alternate_old_new = Code('alternate', '/tmp/launch/plugins/alternate_old_new.o',
                             insertion_point='bgp_local_pref_decision', seq=0,
                             anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                             strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])
    plugin = Plugin("client_choice", 4096, 4096, (alternate_old_new,))
    return PluginManifest((plugin,), jit_all=True)


def pre_script_ifdown(file_path, iface):
    sh_script = """#!/usr/bin/env bash
    
    if [[ $EUID -ne 0 ]]; then
      echo "This script must be run as root" 
      exit 1
    fi
    
    ssh -i /home/thomas/id_rsa root@10.0.0.6 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "ip link set dev {iface} down"
    
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
    
    ssh -i /home/thomas/id_rsa root@10.0.0.6 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "ip link set dev {iface} up"
    
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

    monit = con.new_bgp_node("monitor", suite=EXABGP())
    dut = con.new_bgp_node("dut", suite=strsuite2obj(dut_suite))
    injecter1 = con.new_bgp_node("injecter1", suite=FRR())
    injecter2 = con.new_bgp_node("injecter2", suite=FRR())

    monit.set_as(65022)
    dut.set_as(dut_conf['as'])
    injecter1.set_as(65022)
    injecter2.set_as(65022)

    monit.set_router_id(ip_address("42.0.1.2"))
    dut.set_router_id(ip_address("42.0.2.1"))
    injecter1.set_router_id(ip_address("42.0.2.2"))
    injecter2.set_router_id(ip_address("42.4.0.1"))

    monit.activate_af(IPV4_UNICAST())
    monit.activate_af(IPV6_UNICAST())
    dut.activate_af(IPV4_UNICAST())
    dut.activate_af(IPV6_UNICAST())
    injecter1.activate_af(IPV4_UNICAST())
    injecter1.activate_af(IPV6_UNICAST())
    injecter2.activate_af(IPV4_UNICAST())
    injecter2.activate_af(IPV6_UNICAST())

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


def config_vrf_dut(config_path, suite_str, scenario):
    if scenario is not None:
        scenario.add_metadata('ip_dut_injecter', '42.4.0.2')
        scenario.add_metadata('ip_dut_monitor', '42.0.1.1')
        scenario.add_metadata('ip_injecter', '42.4.0.1')
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


def scenario_frr_vrf(interfaces, memcheck, scenario_name):
    manifest = vrf_manifest(memcheck)
    post_script = post_script_ifup('/tmp/launch/ifup.sh', 'enp16s0f1')
    pre_script = pre_script_ifdown('/tmp/launch/ifdown.sh', 'enp16s0f1')

    manifest.write_conf('/tmp/launch/plugin_manifest.conf')
    extra_args = "-w /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins"

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path='/home/thomas/frr_plugins/sbin', scenario_name=scenario_name,
                        confdir='/tmp/launch/confdir', dut_conf_generator=config_vrf_dut,
                        post_script=post_script, pre_script=pre_script)


def scenario_frr_vrf_memcheck(interfaces):
    return scenario_frr_vrf(interfaces, memcheck=True,
                            scenario_name='frr_memcheck_vrf')
