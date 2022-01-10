#!/usr/bin/env python3
import argparse
import csv
import json
import os
import pathlib
import statistics
import subprocess
import tempfile
from operator import itemgetter
from typing import Callable, TextIO

import numpy as np
import sys

import matplotlib.pyplot as plt

import shlex
from subprocess import run

from posix import EX_USAGE


def run_tshark(info_run, tshark_reader: Callable):
    tshark_filter_command = "bgp.type==2 && ip.src==%s && ip.dst==%s && bgp.update.path_attributes.length > 0" % \
                            (info_run['ip_src'], info_run['ip_dst'])

    if 'nt' in os.name:
        the_tshark_exec = r'"C:\Program Files\Wireshark\tshark.exe"'
        spawn_shell = True
    else:
        the_tshark_exec = "tshark"
        spawn_shell = False

    command = '%s -nr %s -Y "%s" -V -t e -e frame.time_epoch -Tfields' % (
        the_tshark_exec, info_run['pcap_trace'], tshark_filter_command)

    with tempfile.TemporaryFile() as f:
        p = run(command if spawn_shell else shlex.split(command), shell=spawn_shell,
                stdin=None, stderr=None, stdout=f)

        try:
            p.check_returncode()
        except subprocess.CalledProcessError as e:
            print(f"Warning for {info_run['pcap_trace']}\n"
                  f"stderr: {e.stderr.decode()}\n"
                  f"stdout: {e.stdout.decode()}")

        f.seek(0, 0)
        return tshark_reader(f)


def get_first_time(f: 'TextIO'):
    return float(f.readline())


def tail(f, lines=1, _buffer=4098):
    """
    Tail a file and get X lines from the end
    solution from: https://stackoverflow.com/a/13790289
    """
    # place holder for the lines found
    lines_found = []

    # block counter will be multiplied by buffer
    # to get the block size from the end
    block_counter = -1

    # loop until we find X lines
    while len(lines_found) < lines:
        try:
            f.seek(block_counter * _buffer, os.SEEK_END)
        except IOError:  # either file is too small, or too many lines requested
            f.seek(0)
            lines_found = f.readlines()
            break

        lines_found = f.readlines()

        # we found enough lines, get out
        # Removed this line because it was redundant the while will catch
        # it, I left it for history
        # if len(lines_found) > lines:
        #    break

        # decrement the block counter to get the
        # next X bytes
        block_counter -= 1

    return lines_found[-lines:]


def get_last_time(f: 'TextIO'):
    return float(tail(f)[-1])


def make_the_boxplot(args, ylabel='Time (s)'):
    seq_x_boxplot = list()
    labels = list()

    for scenario, times in args:
        seq_x_boxplot.append(times)
        labels.append(scenario)

    plt.boxplot(seq_x_boxplot, labels=labels)
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.show()


def extract_completion_time(traces, metadata):
    times = list()

    for trace in traces:
        print(f"Processing {trace}... ", end='')
        sys.stdout.flush()
        start_time = run_tshark({
            'ip_src': metadata['ip_injecter'],
            'ip_dst': metadata['ip_dut_injecter'],
            'pcap_trace': str(trace)
        }, get_first_time)

        end_time = run_tshark({
            'ip_src': metadata['ip_dut_monitor'],
            'ip_dst': metadata['ip_monitor'],
            'pcap_trace': str(trace)
        }, get_last_time)

        times.append(end_time - start_time)
        print(f"DONE! RIB process: {end_time - start_time}s")

    return times


def save_processed_values(times_per_scenario, output_path):
    field_name = ['scenario', 'time']

    with open(output_path, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=field_name)
        writer.writeheader()

        for scenario, times in times_per_scenario:
            for time in times:
                writer.writerow({
                    'scenario': scenario,
                    'time': time
                })


def plot_from_csv(csv_path):
    parsed_values = dict()

    with open(csv_path) as f:
        csv_reader = csv.DictReader(f)
        for row in csv_reader:
            scenario = row['scenario']
            if scenario not in parsed_values:
                parsed_values[scenario] = list()
            parsed_values[scenario].append(float(row['time']))

    formatted_val = [(key, parsed_values[key]) for key in parsed_values]
    formatted_val.sort(key=itemgetter(0))
    make_the_boxplot(formatted_val)


def plot_from_pcap(pcap_dir, usr_scenario=None, save_output=None):
    times_per_scenario = list()

    scenarios = list()
    if usr_scenario is None:
        metadatas = pathlib.Path(pcap_dir).glob('*.metadata')
        fglob: 'pathlib.Path'
        for fglob in metadatas:
            scenarios.append(fglob.stem)
    else:
        scenarios = usr_scenario

    for scenario in scenarios:
        traces = pathlib.Path(pcap_dir).glob(f'{scenario}*.pcapng')
        meta_data_file = pathlib.Path(pcap_dir, f"{scenario}.metadata")

        with open(meta_data_file) as f:
            metadata = json.load(f)

        times_per_scenario.append((scenario, extract_completion_time(traces, metadata)))

    times_per_scenario.sort(key=itemgetter(0))
    if save_output is not None:
        save_processed_values(times_per_scenario, save_output)

    make_the_boxplot(times_per_scenario)


def main(args):
    if args.csv and args.dir:
        sys.stderr.write("--csv and --dir options cannot be used at the same time\n\n")
        return False

    if args.csv:
        plot_from_csv(args.csv)
        return True

    if not args.dir:
        sys.stderr.write("Either --csv or --dir option must be given to the program\n\n")
        return False

    plot_from_pcap(args.dir, args.scenarios, args.output)
    return True


def reparse_csv(csv_path):
    config_old = [
        {
            'reference': 'bird_native_rr',
            'scenarios': [('bird_rr_memcheck', 'xBIRD RR\nMemcheck'), ('bird_rr_no_memcheck', 'xBIRD RR no\nmemchecks')]
        },
        {
            'reference': 'frr_native_rr',
            'scenarios': [('frr_rr_memcheck', 'xFRR RR\nMemcheck'), ('frr_rr_no_memcheck', 'xFRR RR no\nmemchecks')]
        },
        {
            'reference': 'FRR_Native',
            'scenarios': [('frr_geo_tlv_memcheck', 'xFRR Geo\nTLV MM'),
                          ('frr_geo_tlv_no_memcheck', 'xFRR Geo\nTLV no MM')]
        },
        {
            'reference': 'BIRD_Native',
            'scenarios': [('bird_geo_tlv_memcheck', 'xBIRD Geo\nTLV MM'),
                          ('bird_geo_tlv_no_memcheck', 'xBIRD Geo\nTLV no MM')]
        },
        {
            'reference': 'FRR_Native',
            'scenarios': [('frr_igp_memcheck', 'xFRR\nIGP MM'), ('frr_igp_no_memcheck', 'xFRR IGP\nno MM')]
        },
        {
            'reference': 'BIRD_Native',
            'scenarios': [('bird_igp_memcheck', 'xBIRD\nIGP MM'), ('bird_igp_no_memcheck', 'xBIRD IGP\nno MM')]
        },
        {
            'reference': 'frr_native_2peers',
            'scenarios': [('frr_memcheck_vrf', 'xFRR VRF\nMemchecks'),
                          ('frr_no_memcheck_vrf', 'xFRR VRF no\nMemchecks')]
        },
        {
            'reference': 'BIRD_Native',
            'scenarios': [('bird_pfx_valid_memcheck', 'xBIRD RPKI\nMemchecks'),
                          ('bird_pfx_valid_no_memcheck', 'xBIRD RPKI\nno Memechecks')]
        },
        {
            'reference': 'FRR_Native',
            'scenarios': [('frr_pfx_valid_memcheck', 'xFRR RPKI\nMemchecks'),
                          ('frr_pfx_valid_no_memcheck', 'xFRR RPKI\nno Memchecks')]
        },
    ]

    config = [
        {
            'reference': 'scenario_frr_vrf_native',
            'scenarios': [('frr_no_memcheck_vrf', 'xFRR Route\nSelection (with memchecks)'),
                          ('frr_memcheck_vrf', 'xFRR Route\nSelection (without memchecks)')]
        },
    ]

    cdf = ['frr_memcheck_vrf', 'frr_no_memcheck_vrf']

    parsed_values = dict()

    cdf_data = list()
    final_value = list()

    with open(csv_path) as f:
        csv_reader = csv.DictReader(f)
        for row in csv_reader:
            scenario = row['scenario']
            if scenario not in parsed_values:
                parsed_values[scenario] = list()
            parsed_values[scenario].append(float(row['time']))

    for group in config:
        ref_scenario = group['reference']
        group_median = statistics.median(parsed_values[ref_scenario])
        for scenario, plot_name in group['scenarios']:
            rdata = [(time / group_median) - 1 for time in parsed_values[scenario]]
            final_value.append(
                (plot_name, rdata)
            )
            if scenario in cdf:
                cdf_data.append(rdata)

    line_feed = 'n'

    for exp, process_times in final_value:
        exp_r = exp.replace("\n", " ")
        print(f'{exp_r} -> {statistics.median(process_times)}')

    plot_vrf(cdf_data, ['Route Selection with\nmemory checks', 'Route Selection without\nmemory checks'])
    make_the_boxplot(final_value, ylabel='Relative performance impact')


def plot_vrf(datas, legend):
    lin = list()

    for data in datas:
        N = len(data)
        x = np.sort(data)

        # get the cdf values of y
        y = np.arange(N) / float(N)

        if N > 0:
            x = np.append(x, x[-1])
            y = np.append(y, 1.0)

        line, = plt.step(x, y, marker='o')

        lin.append(line)

    # plt.xlabel('Relative Performance Impact')
    plt.ylabel('CDF')
    plt.legend(lin, legend)
    plt.show()


if __name__ == '__main__':

    reparse_csv("data/rib_vrf.csv")

    exit(0)

    parser = argparse.ArgumentParser(description="Extract time of RIB processing")
    parser.add_argument('-d', '--dir', dest='dir', help='Where to find pcap trace. '
                                                        'This option is not necessary '
                                                        'if --csv is set.',
                        required=False)
    parser.add_argument('-s', '--scenario', dest='scenarios', action='append',
                        help='Which scenario to process. If the option is not '
                             'set, all scenarios located in DIR folder '
                             'will be processed.', required=False)

    parser.add_argument('-c', '--csv', dest='csv', required=False,
                        help='Make the boxplot with csv values instead of pcap files located'
                             'in DIR folder. --csv and --dir options cannot be set altogether')

    parser.add_argument('-o', '--output', dest='output', required=False,
                        help="Store processed time values to this file (value stored in csv format)")

    if not main(parser.parse_args()):
        parser.print_help()
