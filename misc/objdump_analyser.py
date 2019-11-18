#! /usr/bin/env python3
import json
import os
import shlex
import subprocess
import re

from os import EX_OK, EX_USAGE
from sys import argv

__OBJDUMP_PATH__ = "/usr/bin/llvm-objdump"
__CLOC__ = "/usr/bin/cloc"


def cloc(ebpf_path):
    base, _ = os.path.splitext(ebpf_path)

    c_path = base + '.c'

    command = __CLOC__ + " " + c_path

    proc = subprocess.Popen(shlex.split(command),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            universal_newlines=True)

    out = proc.communicate()[0]

    for line in out.split('\n'):
        recv_out = line.strip().strip('\n')

        m = re.match(r'^C\s+\d+\s+\d+\s+\d+\s+(?P<nb_line>\d+)$', recv_out)

        if m:
            return int(m.group('nb_line'))


def analyse_bytecode(ebpf_path):
    command = __OBJDUMP_PATH__ + " -d %s" % ebpf_path

    process = subprocess.Popen(shlex.split(command),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    out, err = process.communicate()

    if process.returncode != EX_OK:
        print("llvm-objdump exited with non zero return value\n%s" % err.decode())
        exit(process.returncode)

    instructions = 0
    external_call = 0

    for line in out.decode().split('\n'):
        matches = re.finditer(r'^\s+\d+:(.)+$', line)

        for match in matches:
            extracted = line[match.start():match.end()].strip()
            instructions += 1
            if extracted.find("call") >= 0:
                external_call += 1

    return {
        "file": os.path.basename(ebpf_path),
        "external_call": external_call,
        "instructions": instructions,
        "size": os.path.getsize(ebpf_path),
        "code": cloc(ebpf_path)
    }


def dict_builder(list_path):
    res = []

    for path in list_path:
        res.append(analyse_bytecode(path))

    return json.dumps(res)


if __name__ == '__main__':
    if len(argv) <= 1:
        print("Must take at least one eBPF bytecode path")
        exit(EX_USAGE)

    print(dict_builder([os.path.abspath(argv[i]) for i in range(1, len(argv))]))
