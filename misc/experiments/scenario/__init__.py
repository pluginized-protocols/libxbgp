from typing import Sequence, Callable

from misc.experiments.scenario.native_scenario import scenario_frr_native, scenario_bird_native
from misc.experiments.scenario.rr_scenario import scenario_frr_plugin_route_reflector_memcheck, \
    scenario_bird_plugin_route_reflector_memcheck, scenario_frr_plugin_route_reflector_no_memcheck, \
    scenario_bird_plugin_route_reflector_no_memcheck


def get_scenarios() -> Sequence[Callable]:
    return [scenario_frr_native, scenario_bird_native, scenario_frr_plugin_route_reflector_memcheck,
            scenario_frr_plugin_route_reflector_no_memcheck, scenario_bird_plugin_route_reflector_memcheck,
            scenario_bird_plugin_route_reflector_no_memcheck]
