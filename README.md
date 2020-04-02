ubpf_tools
==========

`libubpf.a`

About
-----

Library containing a set of helpers to
pluginize a protocol implementation.

Building
--------

Be sure to be on the production branch while building
the project. The master branch is actually the 
development branch pointing to a private version
of the eBPF VM.

The production branch instead points to a public
release of the eBPF VM.

```bash
$ git clone https://bitbucket.org/twirtgen/ubpf_tools.git
$ git checkout production
$ git submodule update --init --recursive
```

The library you will build is relying on some other
dependencies you need to download before linking
libubpf.a inside a protocol implementation :

- json-c 0.12
- CUnit 2.1.3 (to test your build of `libubpf.a`)
- C compiler supporting gnu11 standard
- POSIX thread and XSI extensions
- libmath (`-lm`)

The compilation has been successful with GCC9 and
glibc 2.30.

The below commands are currently supported:
```bash
$ cd ubpf_tools
$ make # build libubpf.a

### run tests ###
$ make check && ./lib_tests --plugin-folder=./tests/plugins
```

Documentation
-------------
Everything is on the `docs` folder.