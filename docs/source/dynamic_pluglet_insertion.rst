=========================
Dynamic pluglet insertion
=========================

Pluglets can be injected while the program is running. libubpf starts a thread to accept eBPF bytecode. It relies
on a kernel queue for this purpose. For the moment, it is only possible to inject bytecode from the same machine.
This prevents that other malicious machine load unexpected bytecode to the main program.

We provide an executable that takes an object ELF file, and then send it to the "pluginized" program. In addition,
the program can replace and remove pluglet as well as removing a whole plugin.

The injecter is named ``ebpf_injecter``. This binary can be used as the following :

.. code-block::

    ebpf_injecter -a action -i plugin_name -m msqid
                  [-p plugin_path]
                  [-h anchor_type]
                  [-e extra_memory]
                  [-s shared_memory]
                  [-n sequence_number]
                  [-j]

-m msqid
   Mandatory argument. It might be the case that multiple "pluginized" programs are running on the same machine (e.g.
   OSPF, BGP and RIP are all "pluginized"). The kernel queue is different on each program. Hence, to tell to
   ``ebpf_injecter`` to send the action on the right program, the kernel queue id must be specified.

   The msqid should normally be written by the libubpf program on a folder (todo: normally should be written
   on the folder specified in the ``init_plugin_manager`` function).

-a action
    Mandatory argument. Specify the action to send to the libubpf. The following actions are valid :

    add
        Add a pluglet to the speficied "pluginized" program. Must be used in conjuction
        with ``-n``, ``-p`` and ``-h`` parameters. ``-j``, ``-e`` and ``-s`` can be used
        to compile in the eBPF code in x86_64 machine code, add extra stack and add a
        shared memory respectively.

    rm
        Remove a whole plugin.

    replace
        Replace a specified pluglet. Must be used in conjuction with ``-n``, ``-p`` and ``-h`` parameters

    rm_pluglet
        Remove a specified pluglet. Must be used in conjuction with ``-n`` and ``-h`` parameters

-i plugin_name
    Mandatory argument. Specify on which plugin the action must be executed. ``plugin_name`` is a string value

-p plugin_path
    Optional argument. If the action is to add or replace a pluglet, this argument must be used to specify the
    path of the ELF eBPF object. The path must be accessible by ``ebpf_injecter``

-h anchor_type
    If ``ebpf_injecter`` is used to add, replace, remove a pluglet, the option specify on which anchor of the plugin
    the action will take place. Valid anchors are :

    pre
        PRE anchor of the plugin

    replace
        REPLACE anchor of the plugin

    post
        POST anchor of the plugin.

-e extra_memory
    Tells the size of the extra stack in bytes.

-s shared_memory
    Tells the size of the shared memory space in bytes.

-n sequence_number
    If the action is requesting changes in the PRE or POST anchor of a plugin, it tells on which pluglet the action
    will take place. The sequence number must be a positive number only.

-j
    Tells if the eBPF pluglet must be compiled in x86_64 machine code.