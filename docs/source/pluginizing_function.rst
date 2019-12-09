=====================
Pluginize C functions
=====================

libubpf is built to add insertion points inside your program so that external eBPF bytecode can be executed.
This section will describe the procedure to
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
Inside an insertion point three type of VM anchor can be executed :

.. image:: pluginized_function.svg
    :alt: Execution flow of a pluginized function compared to a normal function
    :align: center

1. PRE anchor. This anchor can execute multiple bytecode of the same type. It will be executed before any
   instruction of the function. Each bytecode has only a read access to the function, and thus cannot modify
   internal structures of you program.
2. REPLACE anchor. Bytecode associated to this anchor is the actual redefinition of the function body. Hence, it
   can modify the internal data of your program. Since this anchor can actual modify the data, libubpf only allows
   one REPLACE bytecode to be executed for the given insertion point. This will avoid to make undesired effects if
   two bytecode modify the same internal variable.
3. POST anchor. Same as PRE anchor but all the bytecode associated to this anchor will be executed just before
   returning to the calling function (i.e. before finishing the `pluginized` function).



To add an insertion
point to the `find_idx` function described above, libubpf provides macro functions that will do the job for you.
The function, will now become :

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

1. Create an array of argument that will be passed to the bytecode executed in this location of the code.
   This array must be of the type `bpf_args_t`. The fields of this structure are the following :

        .. code-block:: c

            typedef struct bpf_args {
              void *arg;
              size_t len;
              int kind;
              int type;
            } bpf_args_t;

   - *arg* is the pointer of the argument. It is not possible to directly pass the "real" argument since
     the way to pass data to a eBPF bytecode is generic and do not depend on the function to pluginize.
   - *len* is the total size of the argument
   - *kind* whether the argument is a pointer or a primitive. Used by the internal libubpf library
   - *type* is a user custom id, providing extra information about the type of argument. It might be useful later
     when defining custom external API call. This could be a way to check if the argument passed to the external
     function is valid or not.
2. Call the VM_CALL macro. The defintion of the macro is the following :

       .. code-block:: c

           VM_CALL(plugin_id, arguments, number_of_arguments, __VA_ARGS__)

   - *plugin_id* is the numerical identifier corresponding to the insertion point. Since there could be multiple
     insertion points inside a same program, this interger will help libubpf to pick the right bytecode to execute
     when the virtual machine is called.
   - *argument* is the pointer of the array containing the argument to pass to the eBPF bytecode.
   - __VA_ARGS__ is the actual definition of the function. If no bytecode is injected for this function (or
     insertion point)t this will be the code that will be executed instead. The function body must be written
     between two curly brackets to avoid compilation errors.

3. Since the function returns a result, the `return` keyword must be replaced by another marco call :

       .. code-block:: c

           RETURN_VM_VAL(result)

   This macro will first call the POST part of the insertion point for you and then return with the value `result`
   given at argument of the macro.

The case of `void` functions
----------------------------

In the case of a `void` function, another macro is provided for you. Since the POST part of an insertion point is
executed just before the return keyword. As the return keyword could appear everywhere, it is needed to
explicitly change the "return" line by a macro in the case of a "returning" function. However, for a void
function, if the "return" keyword must be summoned, then "nothing" needs to be returned from the function.
Therefore, the two macro functions to use are :

.. code-block:: c

    /* 1 */ VM_CALL_VOID(plugin_id, arguments, number_of_arguments, __VA_ARGS__)
    /* 2 */ RETURN_VM_VOID()

.. note::

    /* 1 \*/ The arguments are the same as VM_CALL defined above. It is not needed to explicitly add the return
    macro at the and of the body definition. The POST anchor is automatically called.

    /* 2 \*/ same as RETURN_VM_VAL but without any arguments. This macro is only intended to be used with
    void functions.

