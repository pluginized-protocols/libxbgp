import pathlib
from ipaddress import ip_address

from experiments.config_generator import Config, FRR, BIRD, IPV4_UNICAST, IPV6_UNICAST, BGPRoute, EXABGP, \
    BGPAttribute, DirIn, DirOut


def config_dut(config_path, dut_suite):
    con = Config(config_path)

    monit = con.new_bgp_node("monitor", suite=EXABGP())
    dut = con.new_bgp_node("dut", suite=dut_suite)
    injecter = con.new_bgp_node("injecter", suite=FRR())

    monit.set_as(65012)
    dut.set_as(65021)
    injecter.set_as(65022)

    monit.set_router_id(ip_address("42.0.1.2"))
    dut.set_router_id(ip_address("42.0.2.1"))
    injecter.set_router_id(ip_address("42.0.2.2"))

    monit.activate_af(IPV4_UNICAST())
    monit.activate_af(IPV6_UNICAST())
    dut.activate_af(IPV4_UNICAST())
    dut.activate_af(IPV6_UNICAST())
    injecter.activate_af(IPV4_UNICAST())
    injecter.activate_af(IPV6_UNICAST())

    n1_neigh_conf, n2_neigh_conf = con.make_link(node1=monit, node2=dut,
                                                 ip_node1=ip_address("42.0.1.2"),
                                                 ip_node2=ip_address("42.0.1.1"))

    dut_neigh_inject_conf, inject_neigh_dut_conf = \
        con.make_link(node1=dut, node2=injecter,
                      ip_node1=ip_address("42.0.2.1"),
                      ip_node2=ip_address("42.0.2.2"))

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

    con.write_conf()

    return dut.output_path, dut.extra_config


def gen_dut_conf(config_path, suite_str: str):
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

    return config_dut(str(dir_path), map_str_to_obj[suite_str])


if __name__ == '__main__':
    print(gen_dut_conf('/tmp/exdir', 'frr'))
