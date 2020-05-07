#! /usr/bin/env python3
import argparse
import json
import os
import shlex
from ipaddress import ip_address
from pathlib import Path
from signal import SIGINT
from subprocess import Popen, PIPE, TimeoutExpired, run, CalledProcessError
from time import sleep
from typing import Union

import pexpect
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

from jsonrpc import JSONRPCResponseManager, dispatcher

STATE_IDLE = 0
STATE_PRE_START_DONE = 1
STATE_RUNNING = 2
STATE_POST_RUN = 3

__CURRENT_DAEMON = None
__STATE_RUN = STATE_IDLE

NOTHING = -1
SOFT_KILL = 0
HARD_KILL = 1

SUPPORTED_IMPLEM = ['frrouting', 'bird']


def query_frrouting(peer_ip, vty_shell: str, vty_args: str = None):
    """
    Return the number of processed prefixes sent by the remote peer given as argument.
    :param vty_shell:
    :param vty_args:
    :param peer_ip: ip address of the peer
    :return: the number of processed prefixes sent by peer_ip
    """

    vty_path = Path(vty_shell)
    if not vty_path.exists():
        return -1

    vty_conn = pexpect.spawn(vty_shell + (' ' + vty_args if not None else ''))
    vty_conn.expect(r"\w+# $")
    vty_conn.sendline("show bgp summary json")

    # trick to remove "show bgp summary" from the command output"
    vty_conn.expect("show bgp summary json")
    vty_conn.expect(r"\w+# $")

    result = vty_conn.before
    result = result.decode()
    # see pexpect doc, each return line is converted to "carriage return-line feed" CRLF because of tty...
    result = result.replace("\r\n", "\n")

    my_json = json.loads(result)
    vty_conn.sendline("exit")

    if 'ipv4Unicast' not in my_json:
        raise ValueError
    if 'peers' not in my_json['ipv4Unicast']:
        raise ValueError
    if str(peer_ip) not in my_json['ipv4Unicast']['peers']:
        raise ValueError

    peer_stats = my_json['ipv4Unicast']['peers'][str(peer_ip)]

    return peer_stats['pfxRcd']


def daemon_killer(daemon) -> int:
    if daemon is None:
        return NOTHING

    daemon.send_signal(SIGINT)
    sleep(3)
    if daemon.poll() is not None:
        daemon.kill()
        return HARD_KILL

    return SOFT_KILL


def run_commands(cmd_list):
    for command in cmd_list:
        try:
            run(shlex.split(command), stdin=None,
                stderr=None, stdout=None).check_returncode()
        except CalledProcessError:
            print("ERROR IN COMMAND !")

    return True


@dispatcher.add_method
def pre_start(**kwargs):
    global __STATE_RUN
    if __STATE_RUN == STATE_PRE_START_DONE:
        return False, "Pre start already done"

    if __STATE_RUN != STATE_IDLE or __STATE_RUN != STATE_POST_RUN:
        return False, "Daemon is already running"

    if 'cmds' not in kwargs:
        return False, "No cmds given"

    run_commands(kwargs['cmds'])  # TODO check return value

    __STATE_RUN = STATE_PRE_START_DONE
    return True, "Ok"


@dispatcher.add_method
def post_shutdown(**kwargs):
    global __STATE_RUN
    if __STATE_RUN != STATE_POST_RUN:
        return False, "Must be called after a run!"

    if 'cmds' not in kwargs:
        return False, "No cmds given"

    run_commands(kwargs['cmds'])  # TODO check return value

    __STATE_RUN = STATE_IDLE
    return True, "Ok"


@dispatcher.add_method
def launch_router(**kwargs):
    global __CURRENT_DAEMON, __STATE_RUN

    if __STATE_RUN != STATE_PRE_START_DONE:
        return False, "Pre start phase missed"

    if __CURRENT_DAEMON is not None:
        return False, "The router is already running"

    if 'launch_conf' not in kwargs:
        return False, "No launch configuration given"

    my_json_str = str(json.dumps(kwargs['launch_conf']))

    proc = Popen(
        shlex.split('python3 ' + my_json_str),
        text=True,
        stderr=PIPE,
        stdout=None,
        stdin=None,
    )

    if proc.poll() is not None:
        __STATE_RUN = STATE_IDLE
        return False, "The launcher was abruptly terminated"

    try:
        _, errs = proc.communicate(timeout=10)

        for line in errs:
            stripped_line = line.strip()
            if '[FAILED]' in stripped_line:
                return False, stripped_line

            if '[INFO] OK' in stripped_line:
                __STATE_RUN = STATE_RUNNING
                __CURRENT_DAEMON = proc
                return True, "OK"

        raise ChildProcessError

    except (TimeoutExpired, ChildProcessError) as e:

        __STATE_RUN = STATE_IDLE

        return_val = daemon_killer(proc)

        if return_val == NOTHING:
            return False, "INTERNAL ERROR (__CURRENT_PROCESS) cannot be None"
        elif return_val == SOFT_KILL:
            if isinstance(e, TimeoutExpired):
                return False, "Child too slow to start"
            return False, "Child does not respect message format"
        else:
            return False, "WARNING: zombie processes may have been created"


@dispatcher.add_method
def stop_router(**kwargs):
    global __CURRENT_DAEMON, __STATE_RUN
    if __CURRENT_DAEMON is None:
        return False, "The router is not launched"

    daemon_killer(__CURRENT_DAEMON)
    __CURRENT_DAEMON = None
    __STATE_RUN = STATE_POST_RUN
    return True, "OK"


@dispatcher.add_method
def query_daemon(**kwargs):
    if __STATE_RUN != STATE_RUNNING:
        # the protocol must run before using this
        return -1

    if 'type' not in kwargs:
        return False
    if 'peer' not in kwargs:
        return False
    if 'vtypath' not in kwargs:
        vty_path = 'vtysh'
    else:
        vty_path = kwargs['vtypath']

    if 'vty_args' in kwargs:
        vty_args = kwargs['vty_args']
    else:
        vty_args = None

    try:
        peer = ip_address(kwargs['peer'])
    except ValueError:
        return False

    if kwargs['type'] not in SUPPORTED_IMPLEM:
        return -1

    if 'frrouting' in kwargs['type']:
        return query_frrouting(peer, vty_path, vty_args)

    return -1


@Request.application
def application(request):
    # Dispatcher is dictionary {<method_name>: callable}
    dispatcher["alive"] = lambda: {"code": True, "status": "yes"}

    response = JSONRPCResponseManager.handle(
        request.get_data(cache=False, as_text=True), dispatcher)
    return Response(response.json, mimetype='application/json')


if __name__ == '__main__':

    if os.getuid() != 0:
        print("Please run this script with root privileges")
        exit(1)

    run_simple('0.0.0.0', 4000, application)
