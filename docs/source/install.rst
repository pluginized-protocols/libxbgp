============
Installation
============

To use the uBPF Library, some dependencies must be satisfied :

- json-c 0.12
- CUnit 2.1.3 to run tests (available `here <https://sourceforge.net/projects/cunit/>`_)
- POSIX threads
- X/Open System Interfaces Extension (message queue and shared memory)
- A C compiler supporting gnu standard (``-std=gnu11``)

Work fine with GCC 9 and glibc 2.30

Getting the Source
------------------
uBPF Library relies on a custom uBPF virtual machine originally built by iovsisor :
https://github.com/iovisor/ubpf. This latter is slightly modified to fit with our
requirements.

To get the code, simply run this command in order to get all the submodules:

.. code-block:: bash

    git clone "https://bitbucket.org/twirtgen/ubpf_tools.git"
    git checkout production
    git submodule update --init --recursive

The stable version of the code is located on the ``production`` branch as the uBPF VM submodule
points to a public version of the Virtual Machine. The ``master`` branch contains the current
development of the libirary with a private version of the uBPF VM.

The library will be statically compiled. Execute this command to get the "libubpf.a" library.
This command must be executed at the root of the ubpf_tool project:

.. code-block:: bash

    make

Include the Library to your Project
-----------------------------------
The freshly built library is intended to "`pluginize`" an existing implementation. In order to be usable, the
`libubpf.a` library and the ``./include`` folder header have to be inserted to your project about
to be pluginized. For example, with both ``gcc`` and ``clang``, use the ``-I`` option to include
the headers and ``-L`` to get the path where ``libubpf.a`` is located. Finally, use ``-lubpf`` to
link the library to the final executable.

You are now ready to add new insertion points inside your existing code.