from typing import Sequence, Callable

from misc.experiments.scenario.geo_tlv_scenario import scenario_frr_geo_tlv_memcheck, scenario_frr_geo_tlv_no_memcheck, \
    scenario_bird_geo_tlv_memcheck, scenario_bird_geo_tlv_no_memcheck
from misc.experiments.scenario.igp_scenario import scenario_frr_igp_memcheck, scenario_frr_igp_no_memcheck, \
    scenario_bird_igp_no_memcheck, scenario_bird_igp_memcheck
from misc.experiments.scenario.native_scenario import scenario_frr_native, scenario_bird_native, \
    scenario_bird_native_2peers, scenario_frr_native_2peers
from misc.experiments.scenario.rpki_scenario import scenario_bird_prefix_validation_memcheck, \
    scenario_bird_prefix_validation_no_memcheck, scenario_frr_prefix_validation_memcheck, \
    scenario_frr_prefix_validation_no_memcheck
from misc.experiments.scenario.rr_scenario import scenario_frr_plugin_route_reflector_memcheck, \
    scenario_bird_plugin_route_reflector_memcheck, scenario_frr_plugin_route_reflector_no_memcheck, \
    scenario_bird_plugin_route_reflector_no_memcheck, scenario_bird_native_route_reflector, \
    scenario_frr_native_route_reflector
from misc.experiments.scenario.vrf_scenario import scenario_frr_vrf_memcheck, scenario_frr_vrf_no_memcheck, \
    scenario_frr_vrf_native


def get_scenarios() -> Sequence[Callable]:
    return [scenario_frr_native, scenario_bird_native,
            scenario_frr_native_2peers, scenario_bird_native_2peers,
            scenario_frr_vrf_native,
            scenario_frr_vrf_memcheck, scenario_frr_vrf_no_memcheck,
            scenario_frr_native_route_reflector,
            scenario_bird_native_route_reflector,
            scenario_frr_plugin_route_reflector_memcheck,
            scenario_frr_plugin_route_reflector_no_memcheck,
            scenario_bird_plugin_route_reflector_memcheck,
            scenario_bird_plugin_route_reflector_no_memcheck,
            scenario_bird_prefix_validation_memcheck,
            scenario_bird_prefix_validation_no_memcheck,
            scenario_frr_prefix_validation_memcheck,
            scenario_frr_prefix_validation_no_memcheck,
            scenario_frr_igp_memcheck,
            scenario_frr_igp_no_memcheck,
            scenario_bird_igp_memcheck,
            scenario_bird_igp_no_memcheck,
            scenario_frr_geo_tlv_memcheck,
            scenario_frr_geo_tlv_no_memcheck,
            scenario_bird_geo_tlv_memcheck,
            scenario_bird_geo_tlv_no_memcheck, ]
