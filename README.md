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
Everything is on the `docs` folder. The documentation is
written with `sphinx` and `sphinx_rtd_theme`. Hence, to
be able to build the documentation, it is needed to first
install `python-sphinx` either via your package manager
or via pip.

When sphinx has been successfully installed, install the
theme according your Python version. Again, it can be
done via pip, by executing `pip install sphinx-rtd-theme`
or via your package manager (`python-sphinx_rtd_theme`).

When the requirements are satisfied, the below commands
build the documentation to be accessed via a web browser:

```bash
$ cd docs
$ make html
``` 

The output are stored at `./ubpf_tools/docs/build/html`.
The file `index.html` is the root html document.

If you want to build the documentation in another format
such as pdf, simply change the output target when
building with `make` (e.g. `make latexpdf`). However,
the html version of the doc is the only one supported
and tested at the time of writing.
