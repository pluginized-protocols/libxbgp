import json
import os
from typing import Callable

from misc.experiments.daemons import Zebra, FRRBGP, BirdBGP


class Scenario(object):
    def __init__(self, interfaces, filename):
        self._daemons_cnf = list()
        self._interface = interfaces  # type: list
        self._out_name_file = filename.strip().replace(' ', '_')
        self._metadata = None

    @property
    def daemons(self):
        return self._daemons_cnf

    @property
    def interfaces(self):
        return self._interface

    @property
    def outfile(self):
        return self._out_name_file

    def add_daemon(self, d: 'Daemon'):
        self._daemons_cnf.append(d)

    def add_metadata(self, key, value):
        if not self._metadata:
            self._metadata = dict()

        self._metadata[key] = value

    def write_metadata(self, outfile):
        if self._metadata is None:
            return
        with open(outfile, 'w') as f:
            json.dump(self._metadata, f)


def set_frr(bin_path, scenario, confs, extra_args=None):
    zebra = Zebra()
    zebra.set_bin_path(os.path.join(bin_path, 'zebra'))
    zebra.set_config_file(confs['zebra'])

    d_frr = FRRBGP()
    d_frr.set_bin_path(os.path.join(bin_path, "bgpd"))
    d_frr.set_config_file(confs['bgp'])
    if extra_args is not None:
        d_frr.set_extra_args(extra_args=extra_args)

    scenario.add_daemon(zebra)
    scenario.add_daemon(d_frr)


def set_bird(bin_path, scenario, confs, extra_args=None):
    bird = BirdBGP()
    bird.set_bin_path(os.path.join(bin_path, 'bird'))
    bird.set_config_file(confs['bgp'])
    if extra_args is not None:
        bird.set_extra_args(extra_args=extra_args)

    scenario.add_daemon(bird)


def set_proto(proto_suite, **args):
    if proto_suite == 'frr':
        set_frr(**args)
    elif proto_suite == 'bird':
        set_bird(**args)
    else:
        raise ValueError(f'Unknown proto_suite {proto_suite}')


def new_scenario(interfaces, routing_suite, bin_path, scenario_name, confdir, dut_conf_generator: Callable,
                 extra_args=None):
    assert (any(routing_suite == x for x in ('frr', 'bird')))

    s = Scenario(interfaces, scenario_name)
    bgp_conf, extra_conf = dut_conf_generator(confdir, routing_suite, s)

    set_proto(routing_suite, bin_path=bin_path, scenario=s,
              confs=dict(extra_conf, bgp=bgp_conf),
              extra_args=extra_args)

    return s
