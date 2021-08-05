from misc.experiments.example_config_generator import gen_dut_conf_rr
from misc.experiments.extra_conf import ExtraConf, ExtraConfVarElemList, ExtraConfVarElemIPv4
from misc.experiments.global_utils import dry_run
from misc.experiments.plugin_conf import Code, Plugin, PluginManifest
from misc.experiments.scenario.scenario_utils import new_scenario


def route_reflector(memcheck):
    strict_check = False if dry_run() else True

    import_rr = Code('import_route_rr', '/tmp/import_route_rr.o',
                     insertion_point='bgp_pre_inbound_filter',
                     seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                     strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    export_rr = Code('export_route_rr', '/tmp/export_route_rr.o',
                     insertion_point='bgp_pre_outbound_filter',
                     seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                     strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    encode_cluster_list = Code('encode_cluster_list', '/tmp/encode_cluster_list.o',
                               insertion_point='bgp_encode_attr',
                               seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                               strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    encode_originator_id = Code('encode_originator_id', '/tmp/encode_originator_id.o',
                                insertion_point='bgp_encode_attr',
                                seq=10, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                                strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    decode_cluster_list = Code('decode_cluster_list', '/tmp/decode_cluster_list.o',
                               insertion_point='bgp_decode_attr',
                               seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                               strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    decode_originator_id = Code('decode_originator', '/tmp/decode_originator.o',
                                insertion_point='bgp_decode_attr',
                                seq=10, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                                strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    plugin = Plugin("route_reflector", 0, 4096, (import_rr, export_rr, encode_cluster_list,
                                                 encode_originator_id, decode_cluster_list,
                                                 decode_originator_id))

    return PluginManifest((plugin,), jit_all=True)


def gen_extra_conf():
    conf = ExtraConf()

    conf.rr_clients = ExtraConfVarElemList()
    conf.rr_clients.append(ExtraConfVarElemIPv4("42.42.1.2"))
    conf.rr_clients.append(ExtraConfVarElemIPv4("42.42.2.2"))
    conf.rr_clients.append(ExtraConfVarElemIPv4("42.0.1.2"))
    conf.rr_clients.append(ExtraConfVarElemIPv4("42.0.2.2"))

    return conf


def scenario_frr_plugin_route_reflector(interfaces, memcheck, scenario_name):
    # -w plugin_manifest
    # -y plugin_dir
    # -a extra_conf_path
    # -x vm_var_state (optional I guess)

    manifest = route_reflector(memcheck)
    extra_conf_plugins = gen_extra_conf()

    extra_conf_plugins.write_conf("/tmp/launch/plugin_extra_conf.conf")
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    extra_args = "-w /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins " \
                 "-a /tmp/launch/plugin_extra_conf.conf"

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path="/home/thomas/frr_plugins/sbin", scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir", dut_conf_generator=gen_dut_conf_rr)


def scenario_frr_plugin_route_reflector_memcheck(interfaces):
    return scenario_frr_plugin_route_reflector(interfaces, memcheck=True,
                                               scenario_name='frr_rr_memcheck')


def scenario_frr_plugin_route_reflector_no_memcheck(interfaces):
    return scenario_frr_plugin_route_reflector(interfaces, memcheck=True,
                                               scenario_name='frr_rr_no_memcheck')


def scenario_bird_plugin_route_reflector(interfaces, memcheck, scenario_name):
    # -x extra_conf_path
    # -y plugin_dir
    # -z plugin_manifest

    manifest = route_reflector(memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    extra_conf_plugins = gen_extra_conf()
    extra_conf_plugins.write_conf("/tmp/launch/plugin_extra_conf.conf")

    extra_args = "-z /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins " \
                 "-x /tmp/launch/plugin_extra_conf.conf"

    return new_scenario(interfaces, routing_suite='bird', extra_args=extra_args,
                        bin_path="/home/thomas/bird_plugin/sbin", scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir", dut_conf_generator=gen_dut_conf_rr)


def scenario_bird_plugin_route_reflector_memcheck(interfaces):
    return scenario_bird_plugin_route_reflector(interfaces, memcheck=True,
                                                scenario_name='bird_rr_memcheck')


def scenario_bird_plugin_route_reflector_no_memcheck(interfaces):
    return scenario_bird_plugin_route_reflector(interfaces, memcheck=False,
                                                scenario_name='bird_rr_no_memcheck')
