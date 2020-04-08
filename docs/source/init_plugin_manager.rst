===============================
Initializing the plugin manager
===============================

In order to use the insertion points defined in your program, the plugin manager has to be initialized.
This must be done with the function call :

.. code-block:: c

    int init_plugin_manager(proto_ext_fun_t *external_function,
                            const char *project_conf_dir,
                            size_t len_char,
                            plugin_info_t *insertion_point,
                            const char *monitoring_address,
                            const char *port,
                            int require_monitoring);

This is the only required function to call on the very beginning of the entry point of your program. The function
takes multiple parameters which are explained below :


external_function
    Is an array of proto_ext_fun_t structure defining an extra external call (see section TODO). The structure
    take the string name of the function and the pointer related to it.
    The last element of this list must be the NULL structure. The library might crash if this termination element
    is omitted

project_conf_dir
    The path associated to the configuration folder of your program.
    It is used to indicate the location of the local state directory, where the library can
    read the JSON manifest path and store files that are used when the eBPF is running.

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
    monitoring listener. Also, if monitoring_address, monitoring_port are not null, and libubpf cannot
    reach the external server, every data sent by plugins will be dropped. However, if require_monitoring is
    set to 1, the manager will wait until a connection is established with the server.

-----------------------------------
Loading bytecode at program startup
-----------------------------------

libubpf provide a function to load plugins from a JSON file. This latter must be formatted on a specific way
to be recognised by the helper. It has the following definition :

.. code-block:: c

    int load_plugin_from_json(const char *path_json,
                              const char *plugin_folder_path,
                              size_t len_plugin_folder_path);


path_json
    Is the path to access to the json containing all the plugins to load when the program starts.

plugin_folder_path
    Default path to the folder containing every plugins referenced in the JSON

len_plugin_folder_path
    Length of the plugin_folder_path string

The JSON file must be structured as the following :

.. code-block:: json

    {
      "jit_all": true,
      "dir": "override/default/path",
      "plugins": {
        "plugin_name_1": {
          "extra_mem": 64,
          "shared_mem": 64,
          "pre": {
            "0": {
              "jit": false,
              "name": "pre_plugin1_seq0.o"
            },
            "25": {
              "jit": true,
              "path": "pre_plugin1_seq25.o"
            },
            "6": {
              "path": "pre_plugin1_seq6.o"
            }
          },
          "replace": {
            "jit": true,
            "path": "replace_plugin1.o"
          },
          "post": {
            "125": {
              "jit": true,
              "path": "post_plugin1_seq125.o"
            },
            "0": {
              "jit": true,
              "path": "post_plugin1_seq0.o"
            }
          }
        },
        "plugin_name_2": {
          "extra_mem": 64,
          "shared_mem": 0,
          "replace": {
            "path": "replace_plugin2.o"
          },
        }
      }
    }

The structure follows the following syntax :

jit_all
    true or false. This is the main directive to tell to libubpf to compile the code in x86_64 machine code
    and then directly execute the machine code when the plugin is called. If the attribute is missing the
    default value is false.

dir
    Path of the folder containing of the eBPF bytecodes. If the variable is missing, libupf take the default
    value passed to the project_conf_dir argument of init_plugin_manager.

plugins
    Is the most important variable since it contains every plugin to be loaded inside the program.
    Each object of this variable takes as key, the name of the plugin such as defined in the array
    insertion_point of the function init_plugin_manager.
    The following keys are now used inside each plugins

        extra_mem
            The number of **bytes** granted to the current plugin. If omitted, no additional memory will be
            provided for the plugin.

        shared_mem
            The number of **bytes** allowed to pass data through different pluglets of the same plugin.
            If omitted no shared memory space is created.

        pre
            contains every pluglet associated to the "pre" hook of the plugin. Each pluglet are associated to
            a sequence number which is the order of execution of the plugin. A smaller number will be thus
            executed before an higher sequence number. Each pluglet can take two more keys :

                jit
                    true or false, override the jit_master choice defined on the root of the JSON object

                name
                    name of the eBPF bytecode. The supported format is ELF. Use a compiler such as clang or gcc
                    to generate an eBPF bytecode of this format.
                    The bytecode must be contained inside the default folder or the path defined in the "dir"
                    variable.

            The pre hook can be omitted. In this case, no pluglet will be attached to the pre hook of the plugin

        replace
            Only one pluglet can be defined for this hook. Hence no sequence number must be provided.

        post
            Same description as the pre hook. All pluglet attached to this hook, will be executed right before
            returning the function associated to the plugin.


-------
Example
-------

Consider this small program :

.. code-block:: c

    int main(int argc, const char *argv[]) {

        start_main_program_loop();
        return EXIT_FAILURE;
    }

Suppose that you put one insertion point called "plugin1" with the ID 1 on a given function
of your program. Suppose also one external call, "external_api_example", you specifically created for your
new insertion point. The new entry point of your program becomes :

.. code-block:: c

    int external_api_example(context_t *ctx, int a) {
        // some stuffs
    }

    int main(int argc, const char *argv[]) {

        int status;

        proto_ext_fun_t funcs[]  = {
            {.name = "external_api_example", .fn = external_api_example },
            plugin_info_null
        }

        plugin_info_t plugins[] = {
            {.plugin_str =  "plugin1", .plugin_id = 1},
            {NULL}
        }

        status = init_plugin_manager(funcs, NULL, 0, plugins, NULL, NULL, 0);
        if (status != 0) return EXIT_FAILURE;

        start_main_program_loop();
        return EXIT_FAILURE;
    }

As the monitoring address and port are set to NULL, eBPF bytecode will not be able to send data to an external
server. Also, the project_conf_dir path is NULL. Hence, it is in the charge of the programmer to manually load
eBPF bytecodes if they must be loaded before executing the first instructions of the real program.

----------------------
Example from FRRouting
----------------------

This little example is taken from one implementation of FRRouting we decided to pluginize.
The variable ``frr_sysconfdir`` contains the path ``/etc/frr``. Hence, every files the
library will create will be contained in ``/etc/frr``

First, the plugin manager is initialized. When no errors occur, static plugins that needs to be loaded
at startup will be so when ``load_plugin_from_json`` is called. The variable ``json_conf`` contains the
manifest of plugin at is loaded at startup (located at ``/etc/frr/manifest.json``). The variable
``plugin_dir`` contains the path folder containing the eBPF byte code to be loaded (on the example
``/etc/frr/plugins``). The folder path can be overrided inside the manifest with the ``dir`` field.

.. code-block:: c

    int must_slash = frr_sysconfdir[strnlen(frr_sysconfdir, PATH_MAX) - 1] == '/' ? 0 : 1;

    char json_conf[PATH_MAX];
    char plugin_dir[PATH_MAX];
    int len = 0;

    memset(json_conf, 0, sizeof(char) * PATH_MAX);
    memset(plugin_dir, 0, sizeof(char) * PATH_MAX);

    snprintf(json_conf, PATH_MAX-1, must_slash? "%s/manifest.json" : "%smanifest.json", frr_sysconfdir);
    len = snprintf(plugin_dir, PATH_MAX-1, must_slash ? "%s/plugins" : "%splugins", frr_sysconfdir);

    if (init_plugin_manager(api_proto, frr_sysconfdir, strnlen(frr_sysconfdir, PATH_MAX), plugin_info,
                            NULL, NULL, 0) != 0) {
        exit(EXIT_FAILURE);
    }


    if (load_plugin_from_json(json_conf, plugin_dir, len) != 0) {
        exit(EXIT_FAILURE);
    }