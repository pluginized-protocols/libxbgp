import json
import pathlib
from typing import Sequence, Union


class Code(object):
    READ = "read"
    WRITE = "write"
    USR_PTR = "usr_ptr"

    REPLACE = "replace"
    PRE = "pre"
    POST = "post"

    def __init__(self, name: str, obj_path: str, insertion_point: str, seq: int, anchor: str,
                 memcheck: bool = True, jit: bool = False, perms: Union[None, Sequence[str]] = None,
                 strict_check: bool = True):
        ebpf_elf = pathlib.Path(obj_path)
        if strict_check and not ebpf_elf.is_file():
            raise ValueError(f"{obj_path} not found as file")
        self.name = name
        self.ebpf_bc = ebpf_elf.name
        self.memcheck = memcheck
        self.jit = jit
        self.insertion_point = insertion_point
        self.seq = seq
        self.perms = set()
        self.anchor = anchor
        if perms:
            for perm in perms:
                if any(perm == x for x in (Code.READ, Code.WRITE, Code.USR_PTR)):
                    self.perms.add(perm)

    def to_dict(self):
        super_json = {
            'obj': self.ebpf_bc,
            'jit': self.jit,
            'add_memcheck': self.memcheck,
        }
        if len(self.perms) > 0:
            super_json['permissions'] = [perm for perm in self.perms]

        return super_json


class Plugin(object):
    def __init__(self, name: str, shared_mem: int, extra_mem: int,
                 obj_list: Union[Sequence['Code'], None]):
        self._name = name
        self._shmem = shared_mem
        self._extra_mem = extra_mem
        self._codes: Sequence['Code'] = [code for code in obj_list] if obj_list is not None else list()

    @property
    def name(self):
        return self._name

    @property
    def codes(self):
        return self._codes

    def add_code(self, code: 'Code'):
        self._codes.append(code)

    def to_dict(self):
        plugin = {
            'extra_mem': self._extra_mem,
            'shared_mem': self._shmem,
            'obj_code_list': dict()
        }

        for code in self._codes:
            plugin['obj_code_list'][code.name] = code.to_dict()

        return plugin


class PluginManifest(object):
    def __init__(self, plugins: Union[None, Sequence['Plugin']] = None, jit_all: bool = False):
        self._plugins = [plugin for plugin in plugins] if plugins is not None else list()
        self._jit_all = jit_all

    def to_dict(self):
        manifest = {
            "jit_all": self._jit_all,
            "plugins": dict(),
            "insertion_points": dict(),
        }

        ipoints = manifest['insertion_points']

        for plugin in self._plugins:
            manifest['plugins'][plugin.name] = plugin.to_dict()

            for code in plugin.codes:
                if code.insertion_point not in ipoints:
                    ipoints[code.insertion_point] = dict()

                if code.anchor not in ipoints[code.insertion_point]:
                    ipoints[code.insertion_point][code.anchor] = dict()

                ipoints[code.insertion_point][code.anchor][code.seq] = code.name

        return manifest

    def to_json(self):
        return json.dumps(self.to_dict())

    def write_conf(self, file):
        with open(file, 'w') as f:
            json.dump(self.to_dict(), f)


def main():
    test = Code("simple_test_api", "/tmp/simple_test_api.o", "add_two_insert_ip", 0, Code.REPLACE,
                memcheck=False, jit=True)

    c1 = Code("pre_simple_ten", "/tmp/pre_simple_ten.o", "full_plugin_ip", 10, Code.PRE,
              memcheck=False, jit=True, perms=[Code.READ, Code.WRITE, Code.USR_PTR])
    c2 = Code("pre_simple_zero", "/tmp/pre_simple_zero.o", "full_plugin_ip", 0, Code.PRE,
              memcheck=False, jit=True)
    c3 = Code("replace_simple", "/tmp/replace_simple.o", "full_plugin_ip", 0, Code.REPLACE,
              memcheck=False, jit=True, perms=[Code.READ, Code.WRITE, Code.USR_PTR])
    c4 = Code("post_simple", "/tmp/post_simple.o", "full_plugin_ip", 0, Code.POST)

    plugin = Plugin("add_two", 64, 64, (test,))
    full = Plugin("full_plugin", 128, 96, (c1, c2, c3, c4))

    manifest = PluginManifest((plugin, full))

    print(manifest.to_json())


if __name__ == '__main__':
    main()
