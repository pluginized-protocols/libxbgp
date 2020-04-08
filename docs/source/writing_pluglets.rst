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

Retrieving Arguments Inside the Plugin
--------------------------------------

As seen in examples, every plugin receives a pointer to its arguments. However, these are not directly
accessible on read. Arguments must be first copied to the memory plugin by the helper function
``bpf_get_args(unsigned int arg_nb, bpf_full_args_t *args);``

`arg_nb`
    The position of the argument to be retrieved

`args`
    Pointer of arguments

Let's suppose this insertion point:

.. code-block:: c

    bpf_args_t args[] = {
        [0] = {.arg = &code, .len = sizeof(code), .kind = kind_primitive, .type = UNSIGNED_INT},
        [1] = {.arg = &flags, .len = sizeof(flags), .kind = kind_primitive, .type = UNSIGNED_INT},
        [2] = {.arg = data, .len = len, .kind = kind_ptr, .type = BYTE_ARRAY},
        [3] = {.arg = &len, .len = sizeof(len), .kind = kind_primitive, .type = UNSIGNED_INT},
        [4] = {.arg = to, .len = sizeof(to), .kind = kind_hidden, .type = ATTRIBUTE_LIST},
        [5] = {.arg = s, .len = sizeof(s), .kind = kind_hidden, .type = PARSE_STATE},
    };

    CALL_REPLACE_ONLY(BGP_DECODE_ATTR, args, sizeof(args) / sizeof(args[0]), ret_val_check_decode, {
        if (!(flags & BAF_OPTIONAL))
            WITHDRAW("Unknown attribute (code %u) - conflicting flags (%02x)", code, flags);
        bgp_decode_unknown(s, code, flags, data, len, to);
    })

The first fourth arguments can be accessed by using ``bpf_get_args``. An example of pluglet executed
inside this insertion point is found below :

.. code-block:: c

    uint64_t generic_decode_attr(bpf_full_args_t *args) {
        uint8_t *code;
        uint16_t *len;
        uint8_t *flags;
        uint8_t *data;

        code = bpf_get_args(0, args);
        flags = bpf_get_args(1, args);
        data = bpf_get_args(2, args);
        len = bpf_get_args(3, args);

        if (!code || !len || !flags || !data) {
            return EXIT_FAILURE;
        }
        return decode_attr(*code, *len, *flags, data) == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

The four arguments is now accessible through the plugin.