from misc.experiments.example_config_generator import gen_dut_conf
from misc.experiments.global_utils import dry_run
from misc.experiments.plugin_conf import Code, Plugin, PluginManifest
from misc.experiments.scenario.scenario_utils import new_scenario


def igp_manifest(memcheck):
    strict_check = False if dry_run() else True

    igp_metric = Code('alternate', '/tmp/launch/plugins/export_igp_metric.o',
                      insertion_point='bgp_pre_inbound_filter', seq=0,
                      anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                      strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])
    plugin = Plugin("igp_check", 0, 4096, (igp_metric,))
    return PluginManifest((plugin,), jit_all=True)


def scenario_frr_igp(interfaces, memcheck, scenario_name):
    manifest = igp_manifest(memcheck=memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # no extra config file
    extra_args = "-w /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins "

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path='/home/thomas/frr_plugins/sbin', scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir", dut_conf_generator=gen_dut_conf)


def scenario_bird_igp(interfaces, memcheck, scenario_name):
    manifest = igp_manifest(memcheck=memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # no extra config file
    extra_args = "-z /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins "

    return new_scenario(interfaces, routing_suite='bird', extra_args=extra_args,
                        bin_path='/home/thomas/bird_plugin/sbin', scenario_name=scenario_name,
                        confdir='/tmp/launch/confdir', dut_conf_generator=gen_dut_conf)


def scenario_frr_igp_memcheck(interfaces):
    return scenario_frr_igp(interfaces, memcheck=True, scenario_name='frr_igp_memcheck')


def scenario_frr_igp_no_memcheck(interfaces):
    return scenario_frr_igp(interfaces, memcheck=False, scenario_name='frr_igp_no_memcheck')


def scenario_bird_igp_memcheck(interfaces):
    return scenario_bird_igp(interfaces, memcheck=True, scenario_name='bird_igp_memcheck')


def scenario_bird_igp_no_memcheck(interfaces):
    return scenario_bird_igp(interfaces, memcheck=False, scenario_name='bird_igp_no_memcheck')
