=====================
Pluginize C functions
=====================

libubpf is built to add insertion points inside your program so that external eBPF bytecode can be executed.
This section will describe the procedure.

Consider a simple function that linearly try to find an object in a sorted array :

.. code-block:: c

    int find_idx(int *array, int key, size_t len) {
      int i;
      for(i = 0; i < len; i++) {
          if (key == array[i]) return i;
      }
      return -1;
    }

This function can be modified to speedup the lookup process. Without the VM, you need to rewrite the function
and then recompile your code to increase this computation. On some programs such as network protocols, it might
be difficult to restart it since it must run 24h/24h. If the above function was inside the protocol library, then
you have to directly change its code. With libubpf, the designer of the library can add insertion points to this
function so that external bytecode can be executed instead of the original function body.

This section will describe the steps to transform this function as being an insertion point for the uBPF virtual
machine.

----------------
Insertion points
----------------

An insertion point is a given location in the code where the virtual machine can be executed.
Inside an insertion point, three types of VM anchor can be executed :

.. image:: _static/pluginized_function.svg
    :alt: Execution flow of a pluginized function compared to a normal function
    :align: center

1. PRE anchor. This anchor can execute multiple bytecode of the same type. It will be executed before any
   instruction of the function. Each bytecode has only read access to the function, and thus cannot modify
   internal structures of your program.
2. REPLACE anchor. Bytecode associated with this anchor is the actual redefinition of the function body. Hence, it
   can modify the internal data of your program. Since this anchor can actually modify the data, libubpf only allows
   one REPLACE bytecode to be executed for the given insertion point. This will avoid making undesired effects if
   two bytecode modify the same internal variable.
3. POST anchor. Same as PRE anchor but all the bytecode associated with this anchor will be executed just before
   returning to the calling function (i.e., before terminating the `pluginized` function).



To add an insertion
point to the `find_idx` function described above, libubpf provides macro functions that will do the job for you.
The function will now become :

.. code-block:: c

    int find_idx(int *array, int key, size_t len) {
      bpf_args_t args[] = {
        {.arg = array, .len = sizeof(*array) * len, .kind = kind_ptr, .type = 0},
        {.arg = &key, .len = sizeof(key), .kind = kind_primitive, .type = 0},
        {.arg = &len, .len = sizeof(len), .kind = kind_primitive, .type = 0}
      }

      VM_CALL(1, args, 3, {
          int i;
          for(i = 0; i < len; i++){
              if (key == array[i]) RETURN_VM_VAL(i);
          }
          RETURN_VM_VAL(-1);
      })
    }

As you can see, the procedure to add an insertion point can be summarized in three major parts :

1. Create an array of arguments that will be passed to the bytecode executed in this location of the code.
   This array must be of the type `bpf_args_t`. The fields of this structure are the following :

        .. code-block:: c

            typedef struct bpf_args {
              void *arg;
              size_t len;
              int kind;
              int type;
            } bpf_args_t;

   - *arg* is the pointer of the argument. It is not possible to directly pass the "real" argument since
     the way to pass data to an eBPF bytecode is generic and does not depend on the function to pluginize.
   - *len* is the total size of the argument
   - *kind* whether the argument is a pointer or a primitive. Used by the internal libubpf library.

     There exist three types of arguments :

     `kind_pointer`
        Used if the data to be passed to the plugin is a pointer to a

     `kind_primitive`
        Used if the data to be transmitted is a pointer to a primitive (``int``, ``char``, ``long``, etc.)

     `kind_hidden`
        This argument will not be directly accessible in the plugin. However, this mechanism could be used to
        pass data to the helper function. Suppose your plugin wants to add a new route to the RIB (routing table)
        of a protocol.
        In normal time, the route will be added through the functions that directly manipulate the RIB. These
        functions can be accessed with helper function. This is fine if the plugin is only dedicated to a
        unique protocol implementation. However, if your plugin needs to support multiple protocol implementation,
        this could be useful to hide the internal representation of the RIB. Since each helper function can
        access to the call context of each eBPF bytecode, the function can retrieve the hidden argument related
        to the RIB.

        Suppose this simple pseudo-code that parses a stream received from a peer:

        .. code-block:: c

            struct routing_table *rib;

            int process_packet(uint8_t *stream) {

                bpf_args_t args[] = {
                    [0] = {.arg = stream, .len = sizeof(*stream), .kind = kind_ptr, .type = STREAM},
                    [1] = {.arg = &flags, .len = sizeof(flags), .kind = kind_hidden, .type = RIB},
                };

                CALL_REPLACE_ONLY(BGP_DECODE_ATTR, args, sizeof(args) / sizeof(args[0]), check_ret_val, {
                    // default code of parsing
                })
            }

        To avoid the plugin to directly expose the pointer of the RIB, we hide the pointer with ``kind_hidden``.
        When the plugin inserts the new parsed route, it will call a helper :

        .. code-block:: c

            int add_route(context_t *ctx, struct *route) {
                struct routing_table *rib;

                bpf_full_args_t *fargs = ctx->args;
                if (fargs->args[1].type == RIB) {
                    rib = fargs->args[i].arg;
                    return add_route_to_rib_internal(rib, route);
                }
            }

        This simple helper function can access to the hidden argument passed to the plugin when called. This has
        multiple advantages :

        1. Since the RIB is an internal structure, its memory is not accessible through the plugin. This is then
           not useful to pass a pointer without any particular meaning to the plugin.

        2. From a security view point, allowing the user to explicitly pass the RIB pointer to the
           helper function may lead to a corruption of the protocol memory. If it does not pass the right pointer,
           the helper function can crash the whole program.

        3. We give a mechanism to abstract the plugin from the host implementation. The plugin does not depend
           on strange structure maintained by the host.


   - *type* is a user custom id, providing extra information about the type of argument. It might be useful later
     when defining custom external API calls. This could be a way to check if the argument passed to the external
     function is valid or not. In the above example, the helper function ``add_route`` checks if the argument is
     of type ``RIB`` before doing the computation.

2. Call the VM_CALL macro. The definition of the macro is the following :

       .. code-block:: c

           VM_CALL(plugin_id, arguments, number_of_arguments, __VA_ARGS__)

   - *plugin_id* is the numerical identifier corresponding to the insertion point. Since there could be multiple
     insertion points inside the same program, this integer will help libubpf to pick the right bytecode to execute
     when the virtual machine is called.
   - *argument* is the pointer of the array containing the argument to pass to the eBPF bytecode.
   - __VA_ARGS__ is the actual definition of the function. If no bytecode is injected for this function (or
     insertion point) this will be the code that will be executed instead. The function body must be written
     between two curly brackets to avoid compilation errors.

3. Since the function returns a result, the `return` keyword must be replaced by another macro call :

       .. code-block:: c

           RETURN_VM_VAL(result)

   This macro will first call the POST part of the insertion point for you and then return to the value `result`
   given to the argument of the macro.

The case of `void` functions
----------------------------

In the case of a `void` function, another macro is provided for you. Since the POST part of an insertion point is
executed just before the return keyword. As the return keyword could appear everywhere, it is needed to
explicitly change the "return" line by a macro in the case of a "returning" function. However, for a void
function, if the "return" keyword must be summoned, then "nothing" needs to be returned to the function.
Therefore, the two macro functions to use are :

.. code-block:: c

    /* 1 */ VM_CALL_VOID(plugin_id, arguments, number_of_arguments, __VA_ARGS__)
    /* 2 */ RETURN_VM_VOID()

.. note::

    /* 1 \*/ The arguments are the same as VM_CALL defined above. It is not needed to explicitly add the return
    macro at the end of the body definition. The POST anchor is automatically called.

    /* 2 \*/ same as RETURN_VM_VAL but without any arguments. This macro is only intended to be used with
    void functions.

"Replace Only" Insertion Point
------------------------------

We also provide a mechanism that only allows an insertion point to only execute the ``REPLACE`` part of
the plugin. Its definition is provided below :

.. code-block:: c

    CALL_REPLACE_ONLY(plug_id, plug_args, nargs, arg_vm_check, on_err, __VA_ARGS__)

`plug_id`
    The ID of the plugin to be executed in this part of the code.

`plug_args`
    The ``bpf_args_t`` array containing the arguments to be passed in the plugin

`nargs`
    The total number of arguments that contains the previous array

`arg_vm_check`
    Function of the type ``int (*arg_vm_check)(uint64_t)`` taking a 64-bits unsigned integer, representing the
    return value of the plugin executed by the virtual machine. This user defined function checks
    if the return value is valid for this execution. If this function returns 0, the macro will fall
    on the on_err branch. Otherwise, if the function returns 1, the macro will switch to the instructions
    located inside the __VA_ARGS__ arguments.

    Let's take this example of call :

    .. code-block:: c

        int ret_val_med_decision(uint64_t val) {
          switch (val) {
            case RTE_NEW:
            case RTE_OLD:
              return 1;
            case RTE_UNK:
            default:
              return 0;
          }
        }

        bpf_args_t this[] = {
          {.arg = new, .len = sizeof(rte), .kind = kind_ptr, .type = BGP_ROUTE},
          {.arg = old, .len = sizeof(rte), .kind = kind_ptr, .type = BGP_ROUTE},
        };

        CALL_REPLACE_ONLY(BGP_MED_DECISION, this, 2, ret_val_med_decision, {
          x = ea_find(new->attrs->eattrs, EA_CODE(PROTOCOL_BGP, BA_MULTI_EXIT_DISC));
          y = ea_find(old->attrs->eattrs, EA_CODE(PROTOCOL_BGP, BA_MULTI_EXIT_DISC));
          n = x ? x->u.data : new_bgp->cf->default_med;
          o = y ? y->u.data : old_bgp->cf->default_med;
          if (n < o)
              return 1;
          if (n > o)
              return 0;
        }, {
          switch (VM_RETURN_VALUE) {
            case RTE_NEW:
              return 1;
            case RTE_OLD:
              return 0;
            default:
              break;
          }
        })

    This code is intended to compare one attribute of two routes pointing to the same IP prefix. In this
    example, the branch ``on_err`` correspond to the case whether the plugins return another value
    than ``RTE_NEW``, ``RTE_OLD``, ``RTE_UNK`` or
    if its execution crashed. The code just fallback on the original decision code of the host
    implementation.

    If the plugin has been correctly executed, and so ``ret_val_med_decision`` returns
    1, the code will continue through the __VA_ARGS__ branch. When the program is on this last branch,
    the MACRO will retrieve the value returned by the plugin and will take action accordingly.

`on_err`
    Branch that will be executed if the function ``arg_vm_check`` returns 0 or if the plugin execution
    due to a runtime error (memory accesses, illegal eBPF instruction, unable to access to the arguments,
    etc.)

`__VA_ARGS__`
    The last branch will be executed if the plugin has not crashed and the ``arg_vm_check`` return 1.

