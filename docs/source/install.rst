============
Installation
============

To use the uBPF Library, some dependencies must be satisfied :

- json-c 0.13.1
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

    git clone --recurse-submodules "https://bitbucket.org/twirtgen/ubpf_tools.git"

The library will be statically compiled. Execute this command to get the "libubpf.a" library.
This command must be executed at the root of the ubpf_tool project:

.. code-block:: bash

    make

Include the Library to your Project
-----------------------------------
The freshly built library is intended to "`pluginize`" an existing implementation. In order to be usable, the
`libubpf.a` library and the ./include/public.h header have to be inserted to your project. You are now ready
to add new insertion points inside your existing code.