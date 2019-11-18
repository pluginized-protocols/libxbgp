#!/usr/bin/env python3

import json
import re
import shlex
import sys
from os import EX_USAGE, path
from subprocess import run

from termcolor import colored

T2_PROOF = None
CFLAGS = None
OK_PROOF = 0
KO_PROOF = 1
UNK_PROOF = 2
PARSE_ERROR = 3

DEBUG_SINGLE_BRANCH = 0


def check_empty_file_t2(c_file_path):
    base = path.basename(c_file_path)
    base = '.'.join(base.split('.')[:-1])
    t2_file = base + ".t2"

    with open(t2_file) as f:
        for s in f:
            if s and not s.isspace():
                return False

    return True


def make_proof(c_file_path, function_name):
    global DEBUG_SINGLE_BRANCH
    command = "%s %s %s '%s'" % (T2_PROOF, c_file_path, function_name, CFLAGS)
    proc = run(shlex.split(command), capture_output=True)

    for line in proc.stdout.decode(sys.stdout.encoding).splitlines():

        lowline = line.lower()

        m = re.search(r'parse error at line (?P<line>\d+)', lowline)

        if m:
            # If there is a parse error, llvm2kittel has generated
            # an empty file; Meaning that the function to analyse
            # contains one single branch (from start to end) that
            # always terminate
            if check_empty_file_t2(c_file_path):
                DEBUG_SINGLE_BRANCH += 1
                return OK_PROOF

            return PARSE_ERROR

        elif "could not parse input file" in lowline:
            DEBUG_SINGLE_BRANCH += 1
            return OK_PROOF
        elif "nontermination proof succeeded" in lowline:
            return KO_PROOF
        elif "termination proof succeeded" in lowline:
            return OK_PROOF
        elif "unhandled exception" in lowline:
            return UNK_PROOF
        elif "unsuitable instructions detected" in lowline:
            return PARSE_ERROR

    print("[Warning] Unable to parse T2 logs (%s)" % path.basename(c_file_path))
    return UNK_PROOF


def make_proofs(json_path):
    global T2_PROOF, CFLAGS

    success = []
    error = []
    parse_error = []
    idk = []

    with open(json_path) as f:
        data = json.load(f)

    T2_PROOF = data['t2_path']
    CFLAGS = data['cflags'] if 'cflags' in data else " "

    assert T2_PROOF is not None
    assert CFLAGS is not None

    for c_code in data['files']:
        proof = make_proof(c_code['path'], c_code['func_name'])
        file = path.basename(c_code['path'])
        if proof == KO_PROOF:
            error.append(file)
            print(colored("[FATAL!] Termination error", 'red', None, ['bold']) +
                  ": %s might not terminate" % file)
        elif proof == UNK_PROOF:
            idk.append(file)
            print(colored("[Warning]", 'yellow', None, ['bold']) + ": unable to proof (non)termination for %s" % file)
        elif proof == PARSE_ERROR:
            parse_error.append(file)
            print(colored("[Warning]", 'cyan', None, ['bold']) + ": can't parse %s" % file)
        else:
            success.append(file)

    print("\nResults:")
    print("  " + colored('Success proofs: ', 'green', None, ['bold']) + str(
        len(success)) + " (including %s function(s) in single branch)" % DEBUG_SINGLE_BRANCH)

    print("  " + colored("I don't know ¯\\_(ツ)_/¯: ", 'yellow', None, ['bold']) + str(len(idk)))
    for f in idk:
        print("    %s" % f)
    print("  " + colored("Parse error: ", 'cyan', None, ['bold']) + str(len(parse_error)))
    for f in parse_error:
        print("    %s" % f)
    print("  " + colored("Nontermination: ", 'red', None, ['bold']) + str(len(error)))
    for f in error:
        print("    %s" % f)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Must take one argument exactly")
        exit(EX_USAGE)

    make_proofs(sys.argv[1])
