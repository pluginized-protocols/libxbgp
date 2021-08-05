import argparse
import csv
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Callable, TextIO

import sys

import matplotlib.pyplot as plt

import shlex
from subprocess import run


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


def make_the_boxplot(args):
    seq_x_boxplot = list()
    labels = list()

    for scenario, times in args:
        seq_x_boxplot.append(times)
        labels.append(scenario)

    plt.boxplot(seq_x_boxplot, labels=labels)
    plt.ylabel('Time (s)')
    plt.grid(True)
    plt.show()


def extract_completion_time(traces, metadata):
    times = list()

    for trace in traces:
        print(f"Processing {trace}...", end='')
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


def main(args):
    times_per_scenario = list()

    for scenario in args.scenarios:
        traces = pathlib.Path(args.dir).glob(f'{scenario}*.pcapng')
        meta_data_file = pathlib.Path(args.dir, f"{scenario}.metadata")

        with open(meta_data_file) as f:
            metadata = json.load(f)

        times_per_scenario.append((scenario, extract_completion_time(traces, metadata)))

    if args.output:
        save_processed_values(times_per_scenario, args.output)

    make_the_boxplot(times_per_scenario)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extract time of RIB processing")
    parser.add_argument('-d', '--dir', dest='dir', help='Where to find pcap trace',
                        required=True)
    parser.add_argument('-s', '--scenario', dest='scenarios', action='append',
                        help='Which scenario to process', required=True)

    parser.add_argument('-o', '--output', dest='output', required=False,
                        help="Store processed time values to this file (value stored in csv format)")

    main(parser.parse_args())
