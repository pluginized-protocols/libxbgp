from misc.experiments.example_config_generator import gen_dut_conf
from misc.experiments.global_utils import dry_run
from misc.experiments.plugin_conf import Code, Plugin, PluginManifest
from misc.experiments.scenario.scenario_utils import new_scenario


def geo_tlv_manifest(memcheck):
    strict_check = False if dry_run() else True

    compare_med = Code('compare_med', '/tmp/launch/plugins/compare_med.o',
                       insertion_point='bgp_med_decision', seq=0,
                       anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                       strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    receive_attr = Code('receive_attr', '/tmp/launch/plugins/receive_attr.o',
                        insertion_point='bgp_decode_attr', seq=0,
                        anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                        strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    write_attr = Code('write_attr', '/tmp/launch/plugins/write_attr.o',
                      insertion_point='bgp_encode_attr', seq=0,
                      anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                      strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    import_pfx_originator = Code('import_pfx_originator', '/tmp/launch/plugins/import_prefix_originator.o',
                                 insertion_point='bgp_pre_inbound_filter', seq=0,
                                 anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                                 strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    set_med_coord = Code('set_med_coord', '/tmp/launch/plugins/set_med_coord.o',
                         insertion_point='bgp_pre_outbound_filter', seq=0,
                         anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                         strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    export_igp_metric = Code('export_igp_metric', '/tmp/launch/plugins/export_igp_metric.o',
                             insertion_point='bgp_pre_outbound_filter', seq=10,
                             anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                             strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    plugin = Plugin("geo_tlv", 0, 4096, (compare_med, receive_attr, write_attr,
                                         import_pfx_originator, set_med_coord,
                                         export_igp_metric))

    return PluginManifest((plugin,), jit_all=True)


def scenario_frr_geo_tlv(interfaces, memcheck, scenario_name):
    manifest = geo_tlv_manifest(memcheck=memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # no extra config file
    extra_args = "-w /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins "

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path='/home/thomas/frr_plugins/sbin', scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir", dut_conf_generator=gen_dut_conf)


def scenario_bird_geo_tlv(interfaces, memcheck, scenario_name):
    manifest = geo_tlv_manifest(memcheck=memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # no extra config file
    extra_args = "-z /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins "

    return new_scenario(interfaces, routing_suite='bird', extra_args=extra_args,
                        bin_path='/home/thomas/bird_plugin/sbin', scenario_name=scenario_name,
                        confdir='/tmp/launch/confdir', dut_conf_generator=gen_dut_conf)


def scenario_frr_geo_tlv_memcheck(interfaces):
    return scenario_frr_geo_tlv(interfaces, memcheck=True, scenario_name='frr_geo_tlv_memcheck')


def scenario_frr_geo_tlv_no_memcheck(interfaces):
    return scenario_frr_geo_tlv(interfaces, memcheck=False, scenario_name='frr_geo_tlv_no_memcheck')


def scenario_bird_geo_tlv_memcheck(interfaces):
    return scenario_bird_geo_tlv(interfaces, memcheck=True, scenario_name='bird_geo_tlv_memcheck')


def scenario_bird_geo_tlv_no_memcheck(interfaces):
    return scenario_bird_geo_tlv(interfaces, memcheck=False, scenario_name='bird_geo_tlv_no_memcheck')
