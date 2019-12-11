================
Helper Functions
================

A pluglet is a contiguous series of eBPF instructions. The eBPF instruction set do not allow making jumps to
another function defined in the bytecode. However, eBPF allows to call functions which are not defined inside
the pluglet bytecode, but rather inside the program where libubpf runs. It can be roughly compared to a Linux
system call.

libubpf provides way to include user defined external functions via the definition of an array :

.. code-block:: c

    proto_ext_fun_t funcs[] = {
            {.name = "add_two", .fn = add_two},
            {.name = "set_int_example", .fn = set_int_example},
            {.name = "post_function_call", .fn = post_function_call},
            {NULL}
    };

This array will be then passed to the init_plugin_manager function when initializing the library. Each entry
of this array takes two fields :

- The string name of the function, as it should be called on eBPF code. The name can be different than the
  one used to define the function. However, if the name has been altered, eBPF code must follow the exact string
  used on this object field.
- The pointer of the function in question

When defining external functions, some precautions must be considered :

1. The external function cannot contain more than 5 arguments. This is a direct limitation of the eBPF
   instruction set.
2. The first argument of the function is **always** a pointer to a context_t structure. The virtual machine
   rewrite each external function call to include a pointer to the execution context of the uBPF VM. This is
   particularly useful to check the validity of some arguments or to allocate memory inside the extra memory
   space of the pluglet.
3. If the function returns a pointer, it must be inside the bound of the allowed memory for the pluglet.
   Otherwise, if the pointer is dereferenced, the eBPF bytecode will crash.

Calling external function inside eBPF bytecode
----------------------------------------------

As previously said, the VM will automatically insert the execution context to the arguments of the helper
function. Suppose you defined an external function as such :

.. code-block:: c

    int add_two(context_t *ctx, int *a);

This helper function will be used inside every bytecode as :

.. code-block:: c

    int add_two(int *a);

The context is intentionally not provided to the bytecode since it contains internal structure of libubpf.
The pointer is located on a memory area not allowed for the plugin. Which means that giving the context to
the eBPF programmer is pretty useless.

However, the context is particularly worthwhile to check the validity of some pointer. When defining arguments
to pass on the plugin, the bpf_args_t structure contains a ``type`` field, which is a user defined integer.
This integer can be used if the pointer given at argument of an helper function is valid.
Consider this small example:

.. code-block:: c

    enum ARGS_TYPE {
        INT_GLOBAL,
        INT_PRIMITIVE
    }

    int some_pluginized_function(int *a, int b) {

        bpf_args_t args[] = {
                {.arg = a, .len = sizeof(*a), .kind = kind_ptr, .type = INT_GLOBAL},
                {.arg = &b, .len = sizeof(b), .kind = kind_primitive, .type = INT_PRIMITIVE},
        };

        VM_CALL(1, args, 2, {
            int new_val;

            new_val =  (*a) * 2 + b;
            *a = new_val;
            RETURN_VM_VAL(new_val);
        })
    }

If you try to write a plugin which reproduce the same behavior as the original function, the modification of the
pointer will be local to the execution of the plugin. Remember that variable is copied inside the VM memory when
the data is requested.

Hence to make the modification of the variable pointer by ``a``, the bytecode has to call an helper function which
will change the variable value. The bytecode associated to this function will then be :

.. code-block:: c

    uint64_t main_replace_function(bpf_full_args_t *args) {
        int new_val;
        int *a = bpf_get_arg(0, args);
        int *b = bpf_get_arg(1, args);

        new_val = (*a) * 2 + b;
        set_int_global(0, args, new_val)
        return new_val;
    }

The external function ``set_int_global`` will set the variable pointed by a to the value of the third argument.
This helper shows the use of the context to check if the call is valid. Here is its definition :

.. code-block:: c

    int set_int_global(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, int new_value) {

        int *a = auto_get(INT_GLOBAL, int *);
        if (!a) return -1;

        *a = new_value;
        return 0;
    }

The helper function contains some interesting instructions that are worth to discuss:

- ``auto_get`` is a macro checking the validity of the argument located at position ``pos_args`` of the
  bytecode ``args``. To use this macro, the first three arguments (and the name associated to the variables)
  must be exactly the same as depicted to the example above. We provide another macro ``api_args`` providing
  the first three arguments to avoid any programming errors. The definition of the same function is then :

  .. code-block:: c

      int set_int_global(api_args, int new_value);

  The function body remains the same. ``auto_get`` is a macro function taking two argument :

  1. The type of argument as defined in the ``bpf_args_t`` array
  2. The type of pointer (cast value)

  ``auto_get`` returns the original pointer to the variable to modify. If the macro cannot check the validity of
  the argument, it returns NULL.
- The pointer returner by ``auto_get`` is the original pointer as defined in the ``bpf_args_t`` array. Any
  changes will be also visible outside the VM