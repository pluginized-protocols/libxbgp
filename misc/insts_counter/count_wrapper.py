#!/usr/bin/env python3

import sys
import argparse
import subprocess
import shlex
import json
import pathlib


def run_counter(file, memcheck=False):
    cmd = './ebpf_insts_counter {memory_check} ' \
          '-e "{elf_file}"'.format(memory_check="" if not memcheck else '-m',
                                   elf_file=file)

    sp = subprocess.run(shlex.split(cmd), shell=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)

    try:
        sp.check_returncode()
    except subprocess.SubprocessError as e:
        sys.stderr.write(f"ebpf_inst_counter returned a non-zero return value code (code {sp.returncode}) :\n"
                         f"stdout: {sp.stdout.decode()}\n"
                         f"stderr: {sp.stderr.decode()}\n")
        sys.exit(1)

    ebpf_stats = json.loads(sp.stdout.decode())

    return ebpf_stats['elf_insts'], ebpf_stats['tot_inst']


def main(args):
    tot_insts_memcheck = 0
    tot_insts_no_memcheck = 0
    tot_elf_insts = 0

    line = "{name: >35}\t{elf: >10}\t{vm_m: >16}\t{vm_nm: >20}"

    print(line.format(name="File", elf="ELF Insts",
                      vm_m="VM Insts (mem)",
                      vm_nm="VM Insts (no mem)"))

    for file in args.ebpf_bc:
        pfile = pathlib.Path(file)
        if not pfile.exists():
            raise FileNotFoundError(file)

        elf_insts, vm_insts_memcheck = run_counter(file=file, memcheck=True)
        _, vm_insts_no_memcheck = run_counter(file=file, memcheck=False)

        tot_elf_insts += elf_insts
        tot_insts_memcheck += vm_insts_memcheck
        tot_insts_no_memcheck += vm_insts_no_memcheck

        print(line.format(name=pfile.name, elf=elf_insts,
                          vm_m=vm_insts_memcheck,
                          vm_nm=vm_insts_no_memcheck))

    print(line.format(name="Total", elf=tot_elf_insts,
                      vm_m=tot_insts_memcheck,
                      vm_nm=tot_insts_no_memcheck))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Count the total number of eBPF instructions in the given files")

    parser.add_argument('ebpf_bc', nargs='+',
                        help='list of ebpf elf file to analyse')

    main(parser.parse_args())
