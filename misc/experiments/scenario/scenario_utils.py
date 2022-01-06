import json
import os
import shlex
import subprocess
from typing import Callable

import sys
import time

from misc.experiments.daemons import Zebra, FRRBGP, BirdBGP, TSHARK
from misc.experiments.global_utils import dry_run


class ExperimentFailedError(Exception):
    pass


class Scenario(object):
    def __init__(self, interfaces, filename, nb_experiments=10, exp_timeout=120, post_exp_wait=100):
        self._daemons_cnf = list()
        self._interface = interfaces  # type: list
        self._out_name_file = filename.strip().replace(' ', '_')
        self._nb_experiments = nb_experiments
        self._exp_timeout = exp_timeout
        self._post_exp_wait = post_exp_wait
        self._metadata = None
        # pre script launched before each experiment
        self._pre_script = None
        # post script launched after each experiment
        self._post_script = None
        # init script launched when the scenario is init
        self._init_script = None
        # fini script launched when the scenario terminates the experiments
        self._fini_script = None

    @property
    def daemons(self):
        return self._daemons_cnf

    @property
    def interfaces(self):
        return self._interface

    @property
    def outfile(self):
        return self._out_name_file

    @property
    def pre_script(self):
        return self._pre_script

    @pre_script.setter
    def pre_script(self, value):
        self._pre_script = value

    @property
    def post_script(self):
        return self._post_script

    @post_script.setter
    def post_script(self, value):
        self._post_script = value

    @property
    def init_script(self):
        return self._init_script

    @init_script.setter
    def init_script(self, value):
        self._init_script = value

    @property
    def fini_script(self):
        return self._fini_script

    @fini_script.setter
    def fini_script(self, value):
        self._fini_script = value

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

    def __spawn_processes(self, outdir, exp_nb, running_daemons):
        tshark = TSHARK(outdir, self.interfaces, self.outfile, exp_nb)

        all_daemons = [tshark]
        all_daemons.extend(self.daemons)

        if dry_run():
            print(f"Launching exp #{exp_nb} {self.outfile} at interface(s) {self.interfaces} "
                  f"with daemons {all_daemons}")
            return

        for daemon in all_daemons:
            proc = subprocess.Popen(
                shlex.split(daemon.get_cmd_line()),
                stderr=sys.stderr,
                stdout=subprocess.DEVNULL,
                stdin=None,
            )

            # tshark is waaaay too slow to start
            time.sleep(2 if daemon.NAME != TSHARK.NAME else 85)

            if proc.poll() is not None:
                raise ChildProcessError("{daemon} couldn't be started!".
                                        format(daemon=daemon))

            running_daemons.add_daemon(proc, daemon.NAME)

    def launch(self, output_dir, daemons):
        self.write_metadata(os.path.join(output_dir, f"{self.outfile}.metadata"))
        err = False

        if self._init_script:
            self._init_script.run()

        for i in range(0, self._nb_experiments):
            if self._pre_script:
                self._pre_script.run()

            try:
                self.__spawn_processes(output_dir, i, daemons)
            except ChildProcessError as e:
                print(f"Experiment failed {e}")
                err = True
            finally:
                if self._post_script:
                    self._post_script.run()

                if not dry_run():
                    time.sleep(self._exp_timeout)
                    daemons.kill_all()
                    # once the daemons has been successfully killed,
                    # we wait a bit to let the other routers to complete
                    # their cleanup because we killed the BGP sessions of
                    # our router but not the remote ones.
                    time.sleep(self._post_exp_wait)

                if err:
                    if self._fini_script:
                        self._fini_script.run()

                    daemons.kill_all()
                    raise ExperimentFailedError()

        if self._fini_script:
            self._fini_script.run()


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
                 extra_args=None, pre_script=None, post_script=None, init_script=None, fini_script=None):
    assert (any(routing_suite == x for x in ('frr', 'bird')))

    s = Scenario(interfaces, scenario_name)
    bgp_conf, extra_conf = dut_conf_generator(confdir, routing_suite, s)

    set_proto(routing_suite, bin_path=bin_path, scenario=s,
              confs=dict(extra_conf, bgp=bgp_conf),
              extra_args=extra_args)

    if pre_script:
        s.pre_script = pre_script

    if post_script:
        s.post_script = post_script

    if init_script:
        s.init_script = init_script

    if fini_script:
        s.fini_script = fini_script

    return s
