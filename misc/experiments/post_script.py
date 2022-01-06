import shlex
import subprocess

import time


class PostScript(object):
    def __init__(self, cmd_script, schedule_time, post_sleep=None) -> None:
        self.cmd_script = cmd_script
        self.schedule_time = schedule_time
        self._post_sleep = post_sleep

    def run(self):
        time.sleep(self.schedule_time)
        p = subprocess.run(shlex.split(self.cmd_script),
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        p.check_returncode()

    def post_sleep(self):
        if self._post_sleep:
            time.sleep(self._post_sleep)


class PreScript(PostScript):
    pass


class InitScript(PostScript):
    pass


class FiniScript(PostScript):
    pass
