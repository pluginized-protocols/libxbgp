from misc.experiments.example_config_generator import gen_dut_conf
from misc.experiments.scenario.scenario_utils import new_scenario


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
