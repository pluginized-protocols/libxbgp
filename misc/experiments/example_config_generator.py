from __future__ import annotations
import pathlib
from ipaddress import ip_address
from typing import Callable, Union

from misc.experiments.config_generator import Config, FRR, BIRD, IPV4_UNICAST, IPV6_UNICAST, BGPRoute, EXABGP, \
    BGPAttribute, DirIn, DirOut, AddressFamilyConfig
from misc.experiments.scenario.scenario_utils import Scenario


def config_dut_rr(config_path, dut_suite, scenario):
    if scenario is not None:
        scenario.add_metadata('ip_dut_injecter', '42.42.2.1')
        scenario.add_metadata('ip_dut_monitor', '42.42.1.1')
        scenario.add_metadata('ip_injecter', '42.42.2.2')
        scenario.add_metadata('ip_monitor', '42.42.1.2')

    return config_dut_generic(config_path, dut_suite, {
        'as': 65022,
        'ip_dut_injecter': "42.42.2.1",
        'ip_dut_monitor': "42.42.1.1",
        'ip_injecter': "42.42.2.2",
        'ip_monitor': "42.42.1.2"
    })


def config_dut_rr_native(config_path, dut_suite, scenario):
    if scenario is not None:
        scenario.add_metadata('ip_dut_injecter', '42.42.2.1')
        scenario.add_metadata('ip_dut_monitor', '42.42.1.1')
        scenario.add_metadata('ip_injecter', '42.42.2.2')
        scenario.add_metadata('ip_monitor', '42.42.1.2')

    return config_dut_generic(config_path, dut_suite, {
        'as': 65022,
        'ip_dut_injecter': "42.42.2.1",
        'ip_dut_monitor': "42.42.1.1",
        'ip_injecter': "42.42.2.2",
        'ip_monitor': "42.42.1.2",
        'rr_clients': ['monitor', 'injecter']
    })


def config_dut(config_path, dut_suite, scenario):
    if scenario is not None:
        scenario.add_metadata('ip_dut_injecter', '42.0.2.1')
        scenario.add_metadata('ip_dut_monitor', '42.0.1.1')
        scenario.add_metadata('ip_injecter', '42.0.2.2')
        scenario.add_metadata('ip_monitor', '42.0.1.2')

    return config_dut_generic(config_path, dut_suite, {
        'as': 65021,
        'ip_dut_injecter': "42.0.2.1",
        'ip_dut_monitor': "42.0.1.1",
        'ip_injecter': "42.0.2.2",
        'ip_monitor': "42.0.1.2"
    })


def config_dut_generic(config_path, dut_suite, dut_conf: dict[str, Union[int, str, list[str]]]):
    con = Config(config_path)

    monit = con.new_node("monitor", suite=FRR())
    dut = con.new_node("dut", suite=dut_suite)
    injecter = con.new_node("injecter", suite=EXABGP())

    bgp_monit = monit.add_bgp_config()
    bgp_dut = dut.add_bgp_config()
    bgp_injecter = injecter.add_bgp_config()

    bgp_monit.set_as(65022)
    bgp_dut.set_as(dut_conf['as'])
    bgp_injecter.set_as(65022)

    monit.set_router_id(ip_address("42.0.1.2"))
    dut.set_router_id(ip_address("42.0.2.1"))
    injecter.set_router_id(ip_address("42.0.2.2"))

    bgp_monit.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_monit.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)
    bgp_dut.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_dut.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter.activate_af(AddressFamilyConfig.AFI_IPV4, AddressFamilyConfig.SAFI_UNICAST)
    bgp_injecter.activate_af(AddressFamilyConfig.AFI_IPV6, AddressFamilyConfig.SAFI_UNICAST)

    n1_neigh_conf, n2_neigh_conf = con.make_link(node1=monit, node2=dut,
                                                 ip_node1=ip_address(dut_conf["ip_monitor"]),
                                                 ip_node2=ip_address(dut_conf["ip_dut_monitor"]))

    dut_neigh_inject_conf, inject_neigh_dut_conf = \
        con.make_link(node1=dut, node2=injecter,
                      ip_node1=ip_address(dut_conf["ip_dut_injecter"]),
                      ip_node2=ip_address(dut_conf["ip_injecter"]))

    n1_neigh_conf.set_holdtime(240)
    n2_neigh_conf.set_holdtime(240)
    n2_neigh_conf.set_description("Send to monitor")
    dut_neigh_inject_conf.set_description("Receive from injector")

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

    dut_neigh_inject_conf.set_filter_acl(perm_all, DirIn())
    dut_neigh_inject_conf.set_filter_acl(block_all, DirOut())
    dut_neigh_inject_conf.set_filter_acl(perm_all6, DirIn())
    dut_neigh_inject_conf.set_filter_acl(block_all6, DirOut())

    if 'rr_clients' in dut_conf:
        if 'injecter' in dut_conf['rr_clients']:
            dut_neigh_inject_conf.set_rr_client()
        if 'monitor' in dut_conf['rr_clients']:
            n2_neigh_conf.set_rr_client()

    con.write_conf()

    return dut.output_path, dut.extra_config


def gen_dut_conf_generic(config_path, suite_str: str, config_gen: Callable, scenario):
    map_str_to_obj = {
        'frr': FRR(),
        'bird': BIRD(),
    }

    assert suite_str in map_str_to_obj, f"Invalid suite: {suite_str}"

    dir_path = pathlib.Path(config_path)

    if not dir_path.exists():
        dir_path.mkdir(parents=True)
    elif not dir_path.is_dir():
        raise ValueError('"{path}" is not a valid directory'.format(path=str(dir_path)))

    return config_gen(str(dir_path), map_str_to_obj[suite_str], scenario)


def gen_dut_conf(config_path, suite_str: str, scenario: Union['Scenario', None]):
    return gen_dut_conf_generic(config_path, suite_str, config_dut, scenario)


def gen_dut_conf_rr(config_path, suite_str: str, scenario: Union['Scenario', None]):
    return gen_dut_conf_generic(config_path, suite_str, config_dut_rr, scenario)


def gen_dut_conf_rr_native(config_path, suite_str, scenario: Union['Scenario', None]):
    return gen_dut_conf_generic(config_path, suite_str, config_dut_rr_native, scenario)


if __name__ == '__main__':
    print(gen_dut_conf('/tmp/exdir', 'bird', None))
