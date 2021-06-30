#! /usr/bin/env python3
import json
import os
import signal
import subprocess
import shlex
import argparse
from abc import ABC
from os import EX_OK, EX_CONFIG, EX_USAGE
from pathlib import Path
from abc import ABC
from typing import Sequence, Callable

import sys
import time
from time import sleep

from experiments.example_config_generator import gen_dut_conf
from experiments.plugin_conf import Code, Plugin, PluginManifest

try:
    from subprocess import DEVNULL  # Python 3.
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

__DRY_RUN = False


class CLIProcess(object):
    NAME = ''

    def get_cmd_line(self):
        raise NotImplementedError()


class Daemon(CLIProcess):
    DAEMONS = dict()

    def __init__(self):
        self._bin = None
        self._config = None
        self._extra_args = ''

    def set_bin_path(self, bin_path):
        self._bin = bin_path

    def set_config_file(self, config):
        self._config = config

    def set_extra_args(self, extra_args):
        self._extra_args = extra_args

    def get_cmd_line(self):
        return ' '.join(
            (self.DAEMONS['path'].format(bin_path=self._bin),
             self.DAEMONS['args'].format(config=self._config,
                                         extra_args=self._extra_args))
        )


class Zebra(Daemon):
    NAME = 'zebra'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f {config} -i/tmp/zebra.pid -z /tmp/zebra.api"
    }


class FRRBGP(Daemon):
    NAME = 'frr'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f {config} -z /tmp/zebra.api -i /tmp/bgpd.pid {extra_args}"
    }


class BirdBGP(Daemon):
    NAME = 'bird'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f -c {config} {extra_args}"
    }


def singleton(real_cls):
    class SingletonFactory(ABC):
        instance = None

        def __new__(cls, *args, **kwargs):
            if not cls.instance:
                cls.instance = real_cls(*args, **kwargs)
            return cls.instance

    SingletonFactory.register(real_cls)
    return SingletonFactory


@singleton
class RunningDaemon(object):
    def __init__(self):
        self._daemons = list()

    def add_daemon(self, daemon, name):
        self._daemons.append((daemon, name))

    def kill_all(self):
        def find_tshark():
            for i in range(0, len(self._daemons)):
                if self._daemons[i][1] == TSHARK.NAME:
                    return i
            return -1

        def dkill(d):
            d.send_signal(signal.SIGINT)
            d.wait()

        # First kill tshark before any routing daemon
        idx = find_tshark()
        if idx >= 0:
            daemon, _ = self._daemons.pop(idx)
            dkill(daemon)

        while len(self._daemons) > 0:
            daemon, _ = self._daemons.pop()
            dkill(daemon)


class TSHARK(CLIProcess):
    NAME = 'tshark'
    exe = {
        'path': 'tshark',
        'args': "-F pcapng {interfaces} -w "
                "{outdir}/{outfile}_{exp_nb}_tshark.pcapng"
    }

    def __init__(self, outdir, interfaces, prefix_file, exp_nb):
        self._outdir = outdir
        self._interfaces = '-i {fmt}'.format(fmt=' -i '.join(interfaces))
        self._prefix_file = prefix_file.replace(' ', '_')
        self._exp_nb = exp_nb

    def get_cmd_line(self):
        return ' '.join((self.exe['path'],
                         self.exe['args'].format(
                             outdir=self._outdir,
                             interfaces=self._interfaces,
                             outfile=self._prefix_file,
                             exp_nb=self._exp_nb)))


def sigint_handler(sig, frame):
    RunningDaemon().kill_all()
    exit(EX_OK)


def launch(interfaces, outdir, prefix_file, exp_nb, daemons_list, daemons: 'RunningDaemon'):
    tshark = TSHARK(outdir, interfaces, prefix_file, exp_nb)

    if __DRY_RUN:
        print(f"Launching exp #{exp_nb} {prefix_file} at interface(s) {interfaces} "
              f"with daemons {daemons_list}")
        return

    for daemon in [tshark] + daemons_list:
        proc = subprocess.Popen(
            shlex.split(daemon.get_cmd_line()),
            stderr=sys.stderr,
            stdout=DEVNULL,
            stdin=None,
        )

        # tshark is waaaay too slow to start
        sleep(1 if daemon.NAME != TSHARK.NAME else 10)

        if proc.poll() is not None:
            raise ChildProcessError("{daemon} couldn't be started!".format(daemon=daemon))

        daemons.add_daemon(proc, daemon.NAME)


class Scenario(object):
    def __init__(self, interfaces, filename):
        self._daemons_cnf = list()
        self._interface = interfaces  # type: list
        self._out_name_file = filename

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


def main(args):
    global __DRY_RUN
    if args.dry_run:
        __DRY_RUN = True

    out_dir = Path(args.output_dir)

    if not out_dir.exists():
        out_dir.mkdir()
    elif not out_dir.is_dir():
        print("{directory} is not a directory !".format(directory=args.output_dir))
        exit(EX_CONFIG)

    # defining multiple scenarios is done in get_scenarios function
    scenario: Callable
    for scenario in get_scenarios():
        s: 'Scenario' = scenario(args.interface)
        for i in range(0, args.nb_experiments):
            launch(s.interfaces, out_dir, s.outfile, i,
                   s.daemons, RunningDaemon())
            # sleep
            if not __DRY_RUN:
                time.sleep(args.timeout)
                RunningDaemon().kill_all()


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


def new_scenario(interfaces, routing_suite, bin_path, scenario_name, confdir, extra_args=None):
    assert (any(routing_suite == x for x in ('frr', 'bird')))

    s = Scenario(interfaces, scenario_name)
    bgp_conf, extra_conf = gen_dut_conf(confdir, routing_suite)

    set_proto(routing_suite, bin_path=bin_path, scenario=s,
              confs=dict(extra_conf, bgp=bgp_conf),
              extra_args=extra_args)

    return s


def scenario_frr_native(interfaces):
    return new_scenario(interfaces, routing_suite='frr', bin_path="/home/thomas/bird_plugin",
                        scenario_name='FRR Native', confdir="/tmp/launch/confdir")


def scenario_bird_native(interfaces):
    return new_scenario(interfaces, routing_suite='bird', bin_path="/home/thomas/bird_plugin",
                        scenario_name='BIRD Native', confdir="/tmp/launch/confdir")


def route_reflector(memcheck):
    strict_check = True
    if __DRY_RUN:
        strict_check = False

    import_rr = Code('import_route_rr', '/tmp/import_route_rr.o',
                     insertion_point='bgp_pre_inbound_filter',
                     seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                     strict_check=strict_check)

    export_rr = Code('export_route_rr', '/tmp/export_route_rr.o',
                     insertion_point='bgp_pre_outbound_filter',
                     seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                     strict_check=strict_check)

    encode_cluster_list = Code('encode_cluster_list', '/tmp/encode_cluster_list.o',
                               insertion_point='bgp_encode_attr',
                               seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                               strict_check=strict_check)

    encode_originator_id = Code('encode_originator_id', '/tmp/encode_originator_id.o',
                                insertion_point='bgp_encode_attr',
                                seq=10, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                                strict_check=strict_check)

    decode_cluster_list = Code('decode_cluster_list', '/tmp/decode_cluster_list.o',
                               insertion_point='bgp_decode_attr',
                               seq=0, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                               strict_check=strict_check)

    decode_originator_id = Code('decode_originator_id', '/tmp/decode_originator_id.o',
                                insertion_point='bgp_decode_attr',
                                seq=10, anchor=Code.REPLACE, jit=True, memcheck=memcheck,
                                strict_check=strict_check)

    plugin = Plugin("route_reflector", 4096, 0, (import_rr, export_rr, encode_cluster_list,
                                                 encode_originator_id, decode_cluster_list,
                                                 decode_originator_id))

    return PluginManifest((plugin,), jit_all=True)


def scenario_frr_plugin_route_reflector(interfaces, memcheck, scenario_name):
    # -w plugin_manifest
    # -y plugin_dir
    # -a extra_conf_path
    # -x vm_var_state (optional I guess)

    manifest = route_reflector(memcheck)
    manifest.write_conf("/tmp/launch/plugin_manifest.conf")
    extra_args = "-w /tmp/launch/plugin_manifest.conf -y /tmp/launch/plugins"

    return new_scenario(interfaces, routing_suite='frr', extra_args=extra_args,
                        bin_path="/home/thomas/bird_plugin", scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir")


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
    extra_args = "-z /tmp/launch/plugin_manifest.conf -y /tmp/launch/plugins"

    return new_scenario(interfaces, routing_suite='bird', extra_args=extra_args,
                        bin_path="/home/thomas/bird_plugin", scenario_name=scenario_name,
                        confdir="/tmp/launch/confdir")


def scenario_bird_plugin_route_reflector_memcheck(interfaces):
    return scenario_bird_plugin_route_reflector(interfaces, memcheck=True,
                                                scenario_name='bird_rr_memcheck')


def scenario_bird_plugin_route_reflector_no_memcheck(interfaces):
    return scenario_bird_plugin_route_reflector(interfaces, memcheck=False,
                                                scenario_name='bird_rr_no_memcheck')


def get_scenarios() -> Sequence[Callable]:
    return [scenario_frr_native, scenario_bird_native, scenario_frr_plugin_route_reflector_memcheck,
            scenario_frr_plugin_route_reflector_no_memcheck, scenario_bird_plugin_route_reflector_memcheck,
            scenario_bird_plugin_route_reflector_no_memcheck]


if __name__ == '__main__':
    if os.getuid() != 0:
        print("Please run this script with root privileges")
        exit(EX_USAGE)

    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", type=str, action='append',
                        required=True, dest='interface')
    parser.add_argument("-o", "--output-dir",
                        required=True, dest='output_dir')
    parser.add_argument("-n", "--nb-experiments", type=int,
                        default=10, dest='nb_experiments')
    parser.add_argument("-p", "--prefix-experiments",
                        required=True, dest='prefix_experiments')
    parser.add_argument("-t", "--timeout", help="Set the maximum time of the experiment",
                        required=True, dest='timeout', type=int)
    parser.add_argument("-d", "--dry-run", dest='dry_run', action='store_true',
                        default=False, help="Do a dry run")

    main(parser.parse_args())
