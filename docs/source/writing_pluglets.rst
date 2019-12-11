================
Writing pluglets
================

Writing eBPF pluglets must follow some conventions to be fully compatible with libubpf. The definition
of the eBPF "main" function is always designed as such :

.. code-block:: c

    #include "/path/to/public_bpf.h"

    uint64_t my_ebpf_bytecode(bpf_full_args_t  *args) {
        ebpf_print("Hello world!\n");
        return BPF_SUCCESS;
    }

This simple function show the required elements to correctly run a function inside :

1. The C code related to the pluglet must include the ``public_bpf.h`` header used to define some pre-included
   header (such as ``ebpf_print`` or the structure ``bpf_full_args_t``)
2. The return value of the function is of type uint64_t since eBPF put the return value to a 64-bits register.
3. If the pluglet is inside the PRE or POST hook, the only considered return values are BPF\_{SUCCESS,FAILURE,CONTINUE}

   The return value of a REPLACE function is the return value of the pluginized function.


Compiling eBPF program
----------------------

Currently, only the ELF object produced by clang (> 3.7) is supported by libubpf. To compile your program located
to the file ``program.c``, execute these commands :

.. code-block:: bash

    clang -I/include/path/of/libubpf -Weverything -O2 -emit-llvm -c program.c -o program.bc
    llc -march=bpf -filetype=obj -o program.o program.bc
    rm program.bc # remove intermediate compilation steps

It will produce a ``program.o`` object file that can be used to load bytecode with libubpf.