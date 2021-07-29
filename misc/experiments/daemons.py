class CLIProcess(object):
    NAME = ''

    def get_cmd_line(self):
        raise NotImplementedError()


class Daemon(CLIProcess):
    DAEMONS = dict()

    def __init__(self):
        self._bin = None
        self._config = None
        self._extra_args = ''

    def set_bin_path(self, bin_path):
        self._bin = bin_path

    def set_config_file(self, config):
        self._config = config

    def set_extra_args(self, extra_args):
        self._extra_args = extra_args

    def __repr__(self):
        return str(self)
        # return f"'{self.get_cmd_line()}'"

    def __str__(self):
        return self.NAME

    def get_cmd_line(self):
        return ' '.join(
            (self.DAEMONS['path'].format(bin_path=self._bin),
             self.DAEMONS['args'].format(config=self._config,
                                         extra_args=self._extra_args))
        )


class Zebra(Daemon):
    NAME = 'zebra'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f {config} -i/tmp/zebra.pid -z /tmp/zebra.api"
    }


class FRRBGP(Daemon):
    NAME = 'frr'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f {config} -z /tmp/zebra.api -i /tmp/bgpd.pid {extra_args}"
    }


class BirdBGP(Daemon):
    NAME = 'bird'
    DAEMONS = {
        'path': "{bin_path}",
        'args': "-f -c {config} {extra_args}"
    }


class TSHARK(CLIProcess):
    NAME = 'tshark'
    exe = {
        'path': 'tshark',
        'args': "-F pcapng {interfaces} -w "
                "{outdir}/{outfile}_{exp_nb}_tshark.pcapng"
    }

    def __init__(self, outdir, interfaces, prefix_file, exp_nb):
        self._outdir = outdir
        self._interfaces = '-i {fmt}'.format(fmt=' -i '.join(interfaces))
        self._prefix_file = prefix_file.replace(' ', '_')
        self._exp_nb = exp_nb

    def get_cmd_line(self):
        return ' '.join((self.exe['path'],
                         self.exe['args'].format(
                             outdir=self._outdir,
                             interfaces=self._interfaces,
                             outfile=self._prefix_file,
                             exp_nb=self._exp_nb)))
