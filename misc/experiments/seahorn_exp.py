#!/usr/bin/env python3
import csv
import pathlib
import shlex
import subprocess
import argparse

import sys
from os import EX_OK


def run_seahorn(relative_path, seahorn_conf, includes, macros):
    includes = "-I%s" % ' -I'.join(includes)
    macros = "-D%s" % ' -D'.join(macros)

    cmdline = f"seahorn_wrapper.py {seahorn_conf} sea bpf --mbc=mono -m64 " \
              f"--inline --track=mem --dsa=sea-cs {macros} {includes} {relative_path}"

    p = subprocess.run(shlex.split(cmdline),
                       shell=False,
                       stdout=subprocess.PIPE)

    if p.returncode != EX_OK:
        print(f"Failed {relative_path}: {p.stdout.decode()}")
        return False, -1

    try:
        time = float(p.stdout.decode())
    except ValueError:
        return False, -1

    return True, time


def expe_loop(nb_time, relative_path, seahorn_conf, includes, macros):
    for _ in range(0, nb_time):
        status, time = run_seahorn(relative_path, seahorn_conf, includes, macros)
        if not status:
            # if the experiment fails, it will fail
            # for the rest of this iteration
            return
        yield time


def main(args):
    p_dir = pathlib.Path(args.dir)

    writer = csv.DictWriter(args.output, fieldnames=['file', 'time'])
    writer.writeheader()
    for file in p_dir.glob("*/*.c"):
        rel_file = file.relative_to(p_dir)

        for time, j in zip(expe_loop(args.nb_exps, rel_file, args.conf,
                                     args.includes, args.defines),
                           range(1, args.nb_exps + 1)):
            print(f"\r[{j}/{args.nb_exps}] {rel_file}", sep='')

            writer.writerow({
                'file': rel_file,
                'time': time
            })
        print("finished !")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nb-exp', dest='nb_exps', type=int, default=10,
                        help='The numbers of experiments to run')
    parser.add_argument('-d', '--dir', dest='dir', type=str, required=True,
                        help="Directory containing plugins to be verified")
    parser.add_argument('-e', '--extension', dest='extension', type=str, default="c")
    parser.add_argument('-c', '--cfg', dest='conf', type=str, required=True,
                        help="seahorn_wrapper config path")
    parser.add_argument('-o', '--output', dest='output', type=argparse.FileType('w'),
                        default=sys.stdout, help="Where to store the results")

    parser.add_argument('-I', dest='includes', action='append', type=str,
                        help='headers to include inside the seahorn container')
    parser.add_argument('-D', dest='defines', action='append', type=str,
                        help='macros')

    main(parser.parse_args())
