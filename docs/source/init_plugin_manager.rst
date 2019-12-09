===============================
Initializing the plugin manager
===============================

In order to use the insertion points defined in your program, the plugin manager has to be initialized.
This must be done with the function call :

.. code-block:: c

    init_plugin_manager(proto_ext_fun_t *external_function, const char *project_conf_dir, size_t len_char,
                        plugin_info_t *insertion_point, const char *monitoring_address, const char *port,
                        int require_monitoring);

This is the only required function to call on the very beginning of the entry point of your program. The function
takes multiple parameters which are explained below :


external_function
    Is an array of proto_ext_fun_t structure defining an extra external call (see section TODO). The structure
    take the string name of the function and the pointer related to it.
    The last element of this list must be the NULL structure. The library might crash if this termination element
    is omitted

project_conf_dir
    The path associated to the configuration folder of your program. It is used to indicate the location of the
    plugin folder and the json required to correctly load eBPF bytecode.

len_char
    Actual size of the `project_conf_dir` string

insertion_point
    Array containing all the insertion point to take into account. This array contains plugin_info_t structure
    which contains two fields:

    1. ***plugin_str*** :  the string name of the actual insertion point.
    2. ***plugin_id*** : the identifier associated to this insertion point

    The string is used in parallel with the json file (TODO). The identifier is used with the definition of an
    insertion point as explained in the "pluginization" section (TODO reference)

monitoring_address
    Some plugins might want to send data to an external exporter to be eventually analysed after. This string
    is either the IP address of the exporter or its domain name

monitoring_port
    The port of the exporter

require_monitoring
    If no plugins are intended to send data, put this argument to 0. This tells to the library to not start the
    monitoring listener. Also, if monitoring_address and monitoring_port are not null, but libubpf cannot
    reach the external server, every data sent by plugins will be dropped. However, if require_monitoring is
    set to 1, then the manager will wait until a connection is established with the server.