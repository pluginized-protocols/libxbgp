import shlex
import subprocess

import time


class PostScript(object):
    def __init__(self, cmd_script, schedule_time) -> None:
        self.cmd_script = cmd_script
        self.schedule_time = schedule_time

    def run(self):
        time.sleep(self.schedule_time)
        p = subprocess.run(shlex.split(self.cmd_script),
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        p.check_returncode()


class PreScript(PostScript):
    pass
