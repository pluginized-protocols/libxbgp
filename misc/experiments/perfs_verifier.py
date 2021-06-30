#!/usr/bin/env python3
import contextlib
import csv
import pathlib
from functools import reduce

import os
import psutil
import shlex
import subprocess

import sys
import time
import argparse

_field_csv = ['name', 'iteration', 'process_time', 'peak_mem', 'realtime']


class FailedProcessError(Exception):
    pass


@contextlib.contextmanager
def smart_open(filename=None):
    if filename and filename != '-':
        fh = open(filename, 'w')
    else:
        fh = sys.stdout

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()


def perfs_process(cmdline, rate):
    data = list()
    tick_time = 1.0 / rate
    attrs = ['status', 'cpu_times', 'memory_full_info', 'create_time']

    start = time.time_ns()
    p = psutil.Popen(shlex.split(cmdline),
                     shell=False,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)

    while p.status() != psutil.STATUS_ZOMBIE:
        time.sleep(tick_time)
        data.append(p.as_dict(attrs=attrs))
    end = time.time_ns()

    # retrieve the latest information when the process terminated
    data.append(p.as_dict(attrs=attrs))
    r_code = p.wait()

    # if r_code != os.R_OK:
    #    raise FailedProcessError("{cmd} returned a non zero value".format(cmd=cmdline))

    return {
        'start': start,
        'end': end,
        'process_info': data
    }


def compute_realtime(data):
    last_cpu_times = data['process_info'][-1]['cpu_times']
    return last_cpu_times.user + last_cpu_times.system


def run_process(name, cmdline, rate, nb_launches):
    results = list()
    for i in range(1, nb_launches + 1):
        print("\rRunning %i/%s for %s" % (i, nb_launches, name), end='')
        data = perfs_process(cmdline, rate)
        records_info = data['process_info']

        results.append({
            'name': name,
            'iteration': i,
            'process_time': (data['end'] - data['start']) / 1e+9,
            'peak_mem': reduce(lambda acc, a: max(acc, a['memory_full_info'].rss +
                                                  a['memory_full_info'].swap),
                               records_info, 0),
            'realtime': compute_realtime(data)
        })
    print("... ok")
    return results


def run_perfs(experiments, save_path, fieldname):
    with smart_open(save_path) as f:
        writer = csv.DictWriter(f, fieldname)
        writer.writeheader()

        for experiment in experiments:
            for record in experiment():
                writer.writerow(record)


def main(args):
    directory = pathlib.Path(args.input_directory)
    lst_file = list(directory.glob("*.{ext}".format(ext=args.extension)))

    exps = list()

    for file in lst_file:
        exps.append(lambda f=file: run_process(f.name, args.command.format(str(f)),
                                               args.rate_sample, args.nb_exp))

    run_perfs(exps, args.output, _field_csv)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rate', '-r', dest="rate_sample", type=int, default=60,
                        help="At which rate the process info should be retrieved (1/s). Default 60 per second")
    parser.add_argument('--exp_nb', '-e', dest="nb_exp", type=int, default=5,
                        help="The number of experiments to make per program")
    parser.add_argument('--dir', '-d', dest="input_directory", type=str, required=True,
                        help="directory containing the programs to verify")
    parser.add_argument("--output", '-o', dest='output', type=str, default='-',
                        help="Location to store the results")
    parser.add_argument('--command', '-c', dest='command', type=str, required=True,
                        help='the command to run the verifier tool ex "cmbc {}". '
                             'The brackets will be replaced by the '
                             'file to be checked.')
    parser.add_argument('--extension', dest='extension', type=str, required=True,
                        help="The program should only consider *.<extension> on the directory")

    main(parser.parse_args())
