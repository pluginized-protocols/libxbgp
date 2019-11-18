//
// Created by thomas on 5/11/18.
//

#include "plugins_manager.h"
#include "ubpf_tools/bgp_ipfix.h"

#include <sys/msg.h>
#include <sys/shm.h>
#include <ubpf_tools/ubpf_prereq.h>
#include <assert.h>
#include <json-c/json_object.h>
#include <stdint.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <pthread.h>
#include <lib/libfrr.h>
#include "ubpf_manager.h"
#include "ubpf_tools/map.h"
#include "defaults.h"
#include "bpf_plugin.h"
#include "ubpf_tools/include/plugin_arguments.h"
#include "ubpf_api.h"

#define ADD_TYPE_OWNPTR 1
#define ADD_TYPE_FILE 2

typedef struct args_plugin_msg_handler {
    int msqid;
    proto_ext_fun_t *protocol;
} args_plugins_msg_hdlr_t;

plugins_t *plugins_manager = NULL;
int already_init = 0;

static int is_directory(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0)
        return 0;
    return S_ISDIR(statbuf.st_mode);
}


argument_type_t get_args_id_by_plug_id(plugin_type_t type) {

    int j;
    int max = sizeof(map_args_plug_id) / sizeof(map_args_plug_id[0]);

    for (j = 0; j < max; ++j)
        if (map_args_plug_id[j].plug_id == type)
            return map_args_plug_id[j].args_id;

    return ARGS_INVALID;

}

int init_plugin_manager(proto_ext_fun_t *api_proto) {

    if (already_init) return 1;

    // start monitor server
    /*if (!main_monitor()) {
        fprintf(stderr, "Starting monitor failed\n");
        return 0;
    }*/

    int i;

    if (plugins_manager) return 1; // already init, exit


    plugins_manager = malloc(sizeof(plugins_t));
    if (!plugins_manager) {
        perror("Cannot create plugin manager");
        return 0;
    }
    plugins_manager->size = 0;

    for (i = 0; i < MAX_PLUGINS; i++) {
        plugins_manager->ubpf_machines[i] = NULL;
    }

    if (init_ubpf_manager(api_proto) != 0) {
        fprintf(stderr, "Can't start ubpf manager\n");
        return 0;
    }

    already_init = 1;

    return 1;
}

static inline plugin_t *get_plugin(int plugin_id) {

    if (!plugins_manager) return NULL;

    if (plugin_id <= 0 || plugin_id >= MAX_PLUGINS)
        return NULL;

    return plugins_manager->ubpf_machines[plugin_id];
}

inline int plugin_is_registered(int id) {

    return get_plugin(id) != NULL;
}

static inline int is_id_in_use(int id) {

    return get_plugin(id) != NULL;

}


static struct json_object *read_json(const char *file_path) {
    FILE *fp;
    char *json_str; // may be big. Hence, allocate memory on the heap
    size_t read_size;
    struct json_object *parsed_json;
    size_t max_size;
    enum json_tokener_error err;

    max_size = 131072; //(128KiB)
    json_str = malloc(max_size * sizeof(char));
    if (!json_str) return NULL; // OOM
    memset(json_str, 0, max_size * sizeof(char));

    fp = fopen(file_path, "r");
    if (!fp) {
        perror("Can't open json file");
        return NULL;
    }

    read_size = fread(json_str, sizeof(char), max_size - 1, fp);
    if (read_size == 0) {
        fprintf(stderr, "Can't read file\n");
        return NULL;
    }
    if (fclose(fp) != 0) return NULL;

    json_str[max_size - 1] = 0;
    parsed_json = json_tokener_parse_verbose(json_str, &err);

    if (err != json_tokener_success) {
        fprintf(stderr, "%s\n", json_tokener_error_desc(err));
        return NULL;
    }
    free(json_str);

    return parsed_json;
}

plugin_type_t id_plugin_to_enum(const char *str) {
    int j;

    int max = sizeof(conversion_id_plugin) / sizeof(conversion_id_plugin[0]);

    for (j = 0; j < max; ++j)
        if (!strncmp(str, conversion_id_plugin[j].str, strlen(conversion_id_plugin[j].str)))
            return conversion_id_plugin[j].val;

    return -1;
}

int load_monit_info(const char *file_path, char *addr, size_t len_addr, char *port, size_t len_port) {

    struct json_object *json;

    struct json_object *port_json = NULL;
    struct json_object *addr_json = NULL;

    const char *port_str = NULL;
    const char *addr_str = NULL;

    memset(addr, 0, sizeof(char) * len_addr);
    memset(port, 0, sizeof(char) * len_port);

    if (!(json = read_json(file_path))) {
        return -1;
    }

    json_object_object_get_ex(json, "port_exporter", &port_json);
    if (port_json) {

        port_str = json_object_get_string(port_json);

        if (port_str)
            strncpy(port, port_str, len_port - 1);


    } else {
        strncpy(port, "4739", 5);
    }
    port[len_port - 1] = 0;

    json_object_object_get_ex(json, "addr_exporter", &addr_json);

    if (addr_json) {

        addr_str = json_object_get_string(addr_json);
        strncpy(addr, addr_str, len_addr - 1);

    } else {
        strncpy(addr, "localhost", 10);
    }

    addr[len_addr - 1] = 0;


    json_object_put(json);

    return 0;

}

int load_from_json(const char *file_path) {

    // TODO: JSON plugin structure must be refactored

    size_t nb_plugins;
    size_t i;
    size_t len_path;

    int err;
    enum json_type json_type;

    char conc_path[PATH_MAX + NAME_MAX + 1];
    char *name_plugin;

    int jit_all, len, final_jit;

    struct json_object *json;
    struct json_object *jit_all_j = NULL;
    struct json_object *plugins_array;
    struct json_object *plugin;

    struct json_object *path;
    struct json_object *extra_mem;
    struct json_object *name;
    struct json_object *id_plugin;
    struct json_object *type;
    struct json_object *shared_mem = NULL;
    struct json_object *dir_json = NULL;
    struct json_object *after = NULL;
    struct json_object *jit = NULL;

    const char *path_str;
    const char *name_str;
    const char *id_plugin_str;
    const char *type_str;
    const char *after_str = NULL;
    const char *dir_obj_file = NULL;

    int extra_mem_int;
    int shared_mem_int;
    int id_plugin_int;
    int jit_bool = 0;
    bpf_plugin_type_placeholder_t type_enum;

    if (!(json = read_json(file_path))) {
        return -1;
    }

    if (!json_object_object_get_ex(json, "plugins", &plugins_array)) {
        return -1; // malformed json
    }
    nb_plugins = json_object_array_length(plugins_array);
    err = 0; // number of plugin not loaded due to errors;

    jit_all = 0;

    json_object_object_get_ex(json, "jit_all", &jit_all_j);
    if (jit_all_j) {
        json_type = json_object_get_type(jit_all_j);
        if (json_type == json_type_boolean) {
            jit_all = json_object_get_boolean(jit_all_j);
        } else {
            fprintf(stderr, "Syntax error\n");
            return -1;
        }
    }

    json_object_object_get_ex(json, "dir", &dir_json);

    memset(conc_path, 0, (PATH_MAX + NAME_MAX + 1) * sizeof(char));

    if (dir_json) {

        dir_obj_file = json_object_get_string(dir_json);
        len_path = json_object_get_string_len(dir_json);
        if (len_path > PATH_MAX) return -1;

        if (access(dir_obj_file, X_OK) != 0) {
            perror("Folder access");
            return -1;
        }
        if (!is_directory(dir_obj_file)) {
            fprintf(stdout, "Not a directory\n");
            return -1;
        }

        strncpy(conc_path, dir_obj_file, len_path);

    } else {
        dir_obj_file = frr_sysconfdir;
        len_path = snprintf(conc_path, PATH_MAX, "%splugins/", dir_obj_file);
    }

    if (conc_path[len_path - 1] != '/') {
        conc_path[len_path] = '/';
        len_path++;
    }

    name_plugin = &conc_path[len_path];

    if (json_object_object_get_ex(json, "shared_mem", &shared_mem)) {
        if (!(shared_mem_int = json_object_get_int(shared_mem))) {
            shared_mem_int = DEFAULT_SHARED_HEAP_SIZE;
        }
    } else {
        shared_mem_int = DEFAULT_SHARED_HEAP_SIZE;
    }

    for (i = 0; i < nb_plugins; i++) {

        jit_bool = 0;
        jit = NULL;
        after_str = NULL;
        after = NULL;

        plugin = json_object_array_get_idx(plugins_array, i);
        if (!plugin) return -1; // ?

        if (!json_object_object_get_ex(plugin, "path", &path)) return -1;
        if (!json_object_object_get_ex(plugin, "extra_mem", &extra_mem)) return -1;
        if (!json_object_object_get_ex(plugin, "name", &name)) return -1;
        if (!json_object_object_get_ex(plugin, "id_plugin", &id_plugin)) return -1;
        if (!json_object_object_get_ex(plugin, "type", &type)) return -1;
        json_object_object_get_ex(plugin, "after", &after);
        json_object_object_get_ex(plugin, "jit", &jit);

        if (!(path_str = json_object_get_string(path))) {
            return -1;
        } else {
            len = json_object_get_string_len(path);
            if (len > NAME_MAX) return -1;

            memset(name_plugin, 0, NAME_MAX + 1);
            strncpy(name_plugin, path_str, len);

        }

        if (!(extra_mem_int = json_object_get_int(extra_mem))) return -1;
        if (!(name_str = json_object_get_string(name))) return -1;
        if (!(id_plugin_str = json_object_get_string(id_plugin))) return -1;
        if (!(type_str = json_object_get_string(type))) return -1;

        if ((id_plugin_int = id_plugin_to_enum(id_plugin_str)) == -1) return -1;
        if ((type_enum = bpf_type_str_to_enum(type_str)) == 0) return -1;

        if (after) {
            if (!(after_str = json_object_get_string(after))) return -1;

            if (type_enum != BPF_POST_APPEND && type_enum != BPF_PRE_APPEND) {
                fprintf(stderr, "\"after\" must only be mentioned with either BFP_PRE_APPEND or BPF_POST_APPEND");
                return -1;
            }
        }

        if (jit) {
            json_type = json_object_get_type(jit);

            switch (json_type) {
                case json_type_boolean:
                    jit_bool = json_object_get_boolean(jit);
                    break;
                default:
                    fprintf(stderr, "Syntax error\n");
                    return -1;
            }

        }


        final_jit = jit ? jit_bool : jit_all; // the most nested jit var is taken (override jit_all)
        if (add_plugin(conc_path, (size_t) extra_mem_int, shared_mem_int, id_plugin_int,
                       type_enum, name_str, final_jit, after_str != NULL ? after_str : NULL) == -1) {
            fprintf(stderr, "Unable to add plugin %s. Abort...\n", name_str);
            err++;
        }

    }

    json_object_put(json);

    return err; // return the number of eBPF code not correctly loaded
}

int is_volatile_plugin(int plug_ID) {
    return plug_ID > BGP_NOT_ASSIGNED_TO_ANY_FUNCTION;
}

static int
__add_plugin_generic(const void *generic_ptr, int id_plugin, int type_plug, int type_ptr,
                     size_t len, size_t add_mem_len, size_t shared_mem, const char *sub_plug_name, const char *after, uint8_t jit,
                     const char **err) {

    plugin_t *plugin_ptr;
    plugin_t *plugin;
    void *bytecode;
    size_t bytecode_len;

    if (!err) {
        fprintf(stderr, "err must not be NULL\n");
        return -1;
    }

    if (id_plugin <= 0 || id_plugin >= MAX_PLUGINS) {
        *err = "id plugin must be strictly greater than 0";
        return -1;
    }

    plugin_ptr = get_plugin(id_plugin);

    if (!plugin_ptr) {
        plugin = init_plugin(add_mem_len, shared_mem, id_plugin);
        if (!plugin) return -1;
        plugins_manager->ubpf_machines[id_plugin] = plugin;
        plugins_manager->size++;
    } else {
        plugin = plugin_ptr;
    }

    switch (type_ptr) {
        case ADD_TYPE_FILE:
            bytecode = readfileOwnPtr(generic_ptr, MAX_SIZE_PLUGIN, &bytecode_len, NULL);
            if (!bytecode) {
                *err = "Cannot allocate memory for bytecode plugin";
                return -1;
            }
            break;
        case ADD_TYPE_OWNPTR:
            bytecode = (void *) generic_ptr;
            bytecode_len = len;
            break;
        default:
            *err = "Pointer passed to add_plugin not recognized";
            return -1;
    }


    switch (type_plug) {
        case BPF_PRE:
            if (add_pre_function(plugin, bytecode, bytecode_len, sub_plug_name, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_POST:
            if (add_post_function(plugin, bytecode, bytecode_len, sub_plug_name, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_REPLACE:
            if (add_replace_function(plugin, bytecode, bytecode_len, sub_plug_name, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_PRE_APPEND:
            if (add_pre_append_function(plugin, bytecode, bytecode_len, after, sub_plug_name, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_POST_APPEND:
            if (add_post_append_function(plugin, bytecode, bytecode_len, after, sub_plug_name, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        default:
            *err = "Cannot recognise the type of plugin";
            return -1;
    }

    if (type_ptr == ADD_TYPE_FILE) free(bytecode);

    return 0;

}

int __add_plugin_ptr(const uint8_t *bytecode, int id_plugin, int type_plugin, size_t len,
                     size_t add_mem_len, size_t shared_mem, const char *sub_plugin_name, const char *after, uint8_t jit,
                     const char **err) {
    return __add_plugin_generic(bytecode, id_plugin, type_plugin, ADD_TYPE_OWNPTR, len, add_mem_len, shared_mem,
                                sub_plugin_name, after, jit, err);
}

int __add_plugin(const char *path_code, int id_plugin, int type_plugin, size_t add_mem_len, size_t shared_mem,
                 const char *sub_plugin_name, const char *after, uint8_t jit, const char **err) {
    return __add_plugin_generic(path_code, id_plugin, type_plugin, ADD_TYPE_FILE, 0, add_mem_len, shared_mem,
                                sub_plugin_name, after, jit, err);
}

int add_plugin(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_plugin,
               const char *sub_plugin_name, uint8_t jit, const char *after) {
    const char *err;
    if (__add_plugin(path_code, id_plugin, type_plugin, add_mem_len, shared_mem, sub_plugin_name, after, jit, &err) == -1) {
        fprintf(stderr, "%s\n", err);
        return -1;
    }
    return 0;
}


int rm_plugin(int id_plugin, const char **err) {

    plugin_t *ptr_plugin;

    if (id_plugin <= 0 || id_plugin > MAX_PLUGINS) {
        *err = PLUGIN_RM_ERROR_ID_NEG;
        return -1;
    }

    if (!is_id_in_use(id_plugin)) {
        *err = PLUGIN_RM_ERROR_404;
        return -1;
    }

    ptr_plugin = plugins_manager->ubpf_machines[id_plugin];

    if (ptr_plugin == NULL) {
        *err = PLUGIN_RM_ERROR_404;
        return -1;
    }
    destroy_plugin(ptr_plugin);
    plugins_manager->ubpf_machines[id_plugin] = NULL;

    plugins_manager->size--;
    *err = NULL;

    return 0;

}

static int
run_plugin_generic(int plug_id, int type, void *mem, size_t mem_len, uint64_t *ret_val) {

    plugin_t *plugin_vm;
    uint64_t return_value; // of code executed by VM
    int exec_ok;
    if (ret_val) *ret_val = EXIT_FAILURE; // will be overwritten when function is executed

    if (!is_id_in_use(plug_id)) {
        //fprintf(stderr, "Plugin not found, id %d not in use\n", plug_id);
        return 0;
    }

    plugin_vm = plugins_manager->ubpf_machines[plug_id];

    if (!plugin_vm) {
        // fprintf(stderr, "Plugin not found (WTF ?) (id nd :%d)\n", plug_id);
        return 0;
    }

    switch (type) {
        case BPF_PRE:
            exec_ok = run_pre_functions(plugin_vm, mem, mem_len, &return_value);
            break;
        case BPF_POST:
            exec_ok = run_post_functions(plugin_vm, mem, mem_len, &return_value);
            break;
        case BPF_REPLACE:
            exec_ok = run_replace_function(plugin_vm, mem, mem_len, &return_value);
            break;
        case BPF_PRE_APPEND:
            exec_ok = run_append_function(plugin_vm, mem, mem_len, &return_value, BPF_PRE_APPEND);
            break;
        case BPF_POST_APPEND:
            exec_ok = run_append_function(plugin_vm, mem, mem_len, &return_value, BPF_POST_APPEND);
            break;
        default:
            fprintf(stderr, "Plugin type not recognized\n");
            return 0;
    }

    if (ret_val) {
        *ret_val = return_value;
        /*if(*ret_val == EXIT_FAILURE)
            fprintf(stderr, "plugin execution encountered an error %s\n", id_plugin_to_str(plug_id));*/
    }

    if (type == BPF_POST_APPEND || type == BPF_PRE_APPEND) {

        if (exec_ok == 0) return 0;
        else return 1;

    } else if (exec_ok != 0) {
        // fprintf(stderr, "No eBPF code has been executed by the VM (%s)\n", id_plugin_to_str(plug_id));
        return 0;
    }

    return 1;
}

int run_plugin_pre(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {
    return run_plugin_generic(plugin_id, BPF_PRE, args, args_len, ret_val);
}

int run_plugin_post(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {
    return run_plugin_generic(plugin_id, BPF_POST, args, args_len, ret_val);
}

int run_plugin_post_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {
    return run_plugin_generic(plugin_id, BPF_POST_APPEND, args, args_len, ret_val);
}

int run_plugin_pre_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {
    return run_plugin_generic(plugin_id, BPF_PRE_APPEND, args, args_len, ret_val);
}

int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {

    plugin_t *pptr;

    if (plugin_id <= 0 || plugin_id > MAX_PLUGINS) return 0;

    pptr = plugins_manager->ubpf_machines[plugin_id];
    if (!pptr) return 0;
    if (!pptr->is_active_replace) return 0; // error + do not execute eBPF bytecode

    return run_plugin_generic(plugin_id, BPF_REPLACE, args, args_len, ret_val);
}

int run_volatile_plugin(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {

    if (!is_volatile_plugin(plugin_id)) return 0;

    if (!run_plugin_pre(plugin_id, args, args_len, ret_val)) {
        // fprintf(stderr, "Volatile PRE successfully failed, unable to continue\n");
        return 0;
    }

    if (!run_plugin_replace(plugin_id, args, args_len, ret_val)) {
        // fprintf(stderr, "Volatile REPLACE execution failed, unable to continue\n");
        return 0;
    }

    if (!run_plugin_post(plugin_id, args, args_len, ret_val)) {
        // fprintf(stderr, "Volatile POST execution failed\n");
        return 0;
    }

    return 1;
}

int init_upbf_inject_queue_snd() {
    return init_ubpf_inject_queue(1); // queue must be created !
}

int init_ubpf_inject_queue_rcv() {
    return init_ubpf_inject_queue(0);
}

int init_ubpf_inject_queue(int type) {
    int msqid;
    int msgflg;
    key_t key;

    switch (type) {
        case 0: // rcv must create the queue
            msgflg = 0600 | IPC_CREAT;
            break;
        case 1:
            msgflg = 0600;
            break;
        default:
            return -1;
    }

    key = ftok(E_BPF_QUEUE_PATH, E_BPF_QUEUE_KEY);
    if (key == -1) {
        perror("ftok can't generate key queue");
        return -1;
    }

    if ((msqid = msgget(key, msgflg)) < 0) {
        perror("msgget");
        return -1;
    }

    return msqid;
}

static inline __off_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        perror("Can't retrieve stats for file");
        return -1;
    }
    return st.st_size;
}

int send_plugin(const char *path, size_t path_len, unsigned int location, unsigned int action, int msqid) {

    ubpf_queue_msg_t msg;
    __off_t size;
    size_t len;

    if (path) {
        if (access(path, R_OK) == -1) {
            perror("Path not accessible in reading");
            return -1; // Can't read ubpf file
        }
        if (path_len > PATH_MAX) {
            fprintf(stderr, "Length path too high");
            return -1;
        }
        if (path[0] != '/') {
            fprintf(stderr, "Path not relative");
            return -1; // the path is relative and not absolute
        }
    } else if (action != E_BPF_ADD && action != E_BPF_REPLACE) { // check if action is not add or replace
        fprintf(stderr, "MISSING PATH...");
        return -1;
    }

    size = file_size(path);
    if (size == -1) return -1;

    if ((len = store_plugin((size_t) size, path)) == 0) {
        return -1;
    }

    assert(len == (size_t) size && "Read length vs actual size differ in size");

    msg.location = location;
    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = action;
    msg.length = len;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Plugin send error [msgsnd]");
        return -1;
    }

    return 0;
}

size_t store_plugin(size_t size, const char *path) {

    int memid;
    key_t key;
    uint8_t *data;
    size_t plugin_length;

    key = ftok(E_BPF_QUEUE_PATH, E_BPF_SHMEM_KEY);

    if (key == -1) {
        perror("Key allocation failed");
        return 0;
    }

    memid = shmget(key, size, 0600);

    if (memid == -1) {
        perror("Unable to retrieve shared memory");
        return 0;
    }

    data = shmat(memid, NULL, 0);

    if (data == (void *) -1) {
        perror("Can't attach shared memory");
        shmctl(memid, IPC_RMID, 0);
        return 0;
    }

    memset(data, 0, size);

    if (!readfileOwnPtr(path, MAX_SIZE_PLUGIN, &plugin_length, data)) {
        fprintf(stderr, "Cannot read bytecode\n");
        return 0;
    }

    shmdt(data);

    return plugin_length;
}

static void *plugin_msg_handler(void *args) {

    ubpf_queue_info_msg_t info;
    args_plugins_msg_hdlr_t *cast_args = args;

    int err = 0;
    const char *str_err;
    int memid;
    uint8_t *data_ptr;
    key_t key;

    info.mtype = MTYPE_INFO_MSG;

    if (!args) {
        fprintf(stderr, "No kernel queue ID received, EXITING...\n");
        exit(EXIT_FAILURE);
    }

    int mysqid = cast_args->msqid;
    ubpf_queue_msg_t rcvd_msg;

    if (!plugins_manager) {
        fprintf(stderr, "Plugin manager not initialised");
        if (!init_plugin_manager(cast_args->protocol)) {
            fprintf(stderr, "Could not start plugin manager, EXITING...\n");
            exit(EXIT_FAILURE);
        }
    }

    key = ftok(E_BPF_QUEUE_PATH, E_BPF_SHMEM_KEY);
    if (key == -1) {
        perror("Key generation failed");
        return NULL;
    }

    memid = shmget(key, MAX_SIZE_PLUGIN, IPC_CREAT | 0600);

    if (memid == -1) {
        perror("Shared memory creation failed");
        return NULL;
    }

    data_ptr = shmat(memid, NULL, 0);
    if ((void *) data_ptr == (void *) -1) {
        shmctl(memid, IPC_RMID, NULL);
        return NULL;
    }

    while (1) { // TODO additional memory in CLI (static now) see __add_plugin_ptr calls -> dynamic or static ?
        err = 0;
        memset(&rcvd_msg, 0, sizeof(ubpf_queue_msg_t));
        memset(info.reason, 0, sizeof(char) * MAX_REASON);

        if (msgrcv(mysqid, &rcvd_msg, sizeof(ubpf_queue_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
            continue;
            //perror("msgrcv");
            //remove_xsi();
        }

        switch (rcvd_msg.plugin_type) {
            case BPF_PRE:
            case BPF_POST:
            case BPF_REPLACE:
                break;
            default:
                fprintf(stderr, "Unrecognized plugin type\n");
                err = 1;
                goto end;
        }

        switch (rcvd_msg.plugin_action) {
            case E_BPF_ADD:
                if (__add_plugin_ptr(data_ptr, rcvd_msg.location, rcvd_msg.plugin_type,
                                     rcvd_msg.length, 0, 0, rcvd_msg.name, rcvd_msg.after, rcvd_msg.jit, &str_err) < 0) {
                    err = 1;
                    strncpy(info.reason, str_err, strlen(str_err));
                }
                break;
            case E_BPF_RM:
                if (rm_plugin(rcvd_msg.location, &str_err) == -1) {
                    err = 1;
                    strncpy(info.reason, str_err, strlen(str_err));
                }
                break;
            case E_BPF_REPLACE:
                if (rm_plugin(rcvd_msg.location, &str_err) == -1) {
                    err = 1;
                    strncpy(info.reason, str_err, strlen(str_err));
                } else if (
                        __add_plugin_ptr(data_ptr, rcvd_msg.location, rcvd_msg.plugin_type,
                                         rcvd_msg.length, 0,0, rcvd_msg.name, rcvd_msg.after, rcvd_msg.jit, &str_err) <
                        0) {
                    err = 1;
                    strncpy(info.reason, str_err, strlen(str_err));
                }
                break;
            default:
                fprintf(stderr, "Unrecognised msg type (%s)\n", __func__);
                break;
        }

        end:

        if (err) {
            info.status = -1;
        } else {
            info.status = 0;
            strncpy(info.reason, PLUGIN_OK, strlen(PLUGIN_OK) + 1);
        }

        if (msgsnd(mysqid, &info, sizeof(ubpf_queue_info_msg_t), 0) != 0) {
            perror("Can't send confirmation to extern process");
        }

    }

}

void start_ubpf_plugin_listener(proto_ext_fun_t *fn) {

    args_plugins_msg_hdlr_t *args;
    int msqid;

    pthread_t data;

    args = malloc(sizeof(args_plugins_msg_hdlr_t));
    if (!args) {
        perror("Thread args malloc failure");
        exit(EXIT_FAILURE);
    }

    msqid = init_ubpf_inject_queue_rcv();

    args->msqid = msqid;
    args->protocol = fn;

    if (msqid == -1) {
        fprintf(stderr, "Unable to start dynamic plugin injection\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&data, NULL, &plugin_msg_handler, args) != 0) {
        fprintf(stderr, "Unable to create thread for dynamic plugin injection\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(data) != 0) {
        fprintf(stderr, "Detachment of the thread failed (%s)", __func__);
        exit(EXIT_FAILURE);
    }

}

int notify_deactivate_replace(plugins_t *pm, int plugin_id) {
    plugin_t *p_ptr, *p;
    if (!pm) return -1;

    if (plugin_id <= 0 || plugin_id > MAX_PLUGINS) return -1;

    p_ptr = plugins_manager->ubpf_machines[plugin_id];

    if (!p_ptr) return -1;
    p = p_ptr;

    p->is_active_replace = 0;

    return 0;
}

void remove_xsi() {

    int msqid, memid;
    key_t msqkey, memkey;

    msqkey = ftok(E_BPF_QUEUE_PATH, E_BPF_QUEUE_KEY);
    if (msqkey == -1) {
        perror("Can't generate key");
    }
    memkey = ftok(E_BPF_QUEUE_PATH, E_BPF_SHMEM_KEY);
    if (memkey == -1) {
        perror("Can't generate key");
    }

    msqid = msgget(msqkey, 0600);

    if (msqid == -1) {
        perror("Can't get message queue");
    }

    memid = shmget(memkey, MAX_SIZE_PLUGIN, 0600);

    if (memid == -1) {
        perror("Can't get shared memory");
    }

    shmctl(memid, IPC_RMID, NULL);
    msgctl(msqid, IPC_RMID, NULL);

    rm_ipc();

}