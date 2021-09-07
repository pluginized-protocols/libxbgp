from misc.experiments.example_config_generator import gen_dut_conf
from misc.experiments.global_utils import dry_run
from misc.experiments.plugin_conf import Code, Plugin, PluginManifest
from misc.experiments.scenario.scenario_utils import new_scenario


def rpki_manifest(memcheck):
    strict_check = False if dry_run() else True

    prefix_validation = Code('pfx_validation', '/tmp/prefix_validator.o',
                             insertion_point='bgp_pre_inbound_filter', seq=0,
                             anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                             strict_check=strict_check, perms=[Code.READ, Code.WRITE, Code.USR_PTR])

    plugin = Plugin("prefix_validator", 0, 4096, (prefix_validation,))
    return PluginManifest((plugin,), jit_all=True)


def scenario_frr_prefix_validation(interfaces, memcheck, scenario_name):
    manifest = rpki_manifest(memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # extra conf generated outside this script !!
    extra_args = "-w /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins " \
                 "-a /tmp/launch/plugin_extra_conf.conf"

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path="/home/thomas/frr_plugins/sbin", scenario_name=scenario_name,
                        confdir='/tmp/launch/confdir', dut_conf_generator=gen_dut_conf)


def scenario_bird_prefix_validation(interfaces, memcheck, scenario_name):
    manifest = rpki_manifest(memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    # extra conf generated outside this script
    extra_args = "-z /tmp/launch/plugin_manifest.conf " \
                 "-y /tmp/launch/plugins " \
                 "-x /tmp/launch/plugin_extra_conf.conf"

    return new_scenario(interfaces, routing_suite='bird', extra_args=extra_args,
                        bin_path="/home/thomas/bird_plugin/sbin", scenario_name=scenario_name,
                        confdir='/tmp/launch/confdir', dut_conf_generator=gen_dut_conf)


def scenario_bird_prefix_validation_memcheck(interfaces):
    return scenario_bird_prefix_validation(interfaces, memcheck=True, scenario_name="bird_pfx_valid_memcheck")


def scenario_bird_prefix_validation_no_memcheck(interfaces):
    return scenario_bird_prefix_validation(interfaces, memcheck=False, scenario_name="bird_pfx_valid_no_memcheck")


def scenario_frr_prefix_validation_memcheck(interfaces):
    return scenario_frr_prefix_validation(interfaces, memcheck=True, scenario_name="frr_pfx_valid_memcheck")


def scenario_frr_prefix_validation_no_memcheck(interfaces):
    return scenario_frr_prefix_validation(interfaces, memcheck=False, scenario_name="frr_pfx_valid_no_memcheck")
