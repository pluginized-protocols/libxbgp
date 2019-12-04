//
// Created by thomas on 5/11/18.
//

#include "plugins_manager.h"

#include <sys/msg.h>
#include <sys/shm.h>
#include <ubpf_misc.h>
#include <assert.h>
#include <json-c/json_object.h>
#include <stdint.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <pthread.h>
#include "ubpf_manager.h"
#include "map.h"
#include "bpf_plugin.h"
#include "include/plugin_arguments.h"
#include "ubpf_api.h"
#include "monitoring_server.h"
#include "ubpf_context.h"

#include <stdio.h>

#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>

#define ADD_TYPE_OWNPTR 1
#define ADD_TYPE_FILE 2

static void *plugin_msg_handler(void *args);

typedef struct args_plugin_msg_handler {
    int msqid;
} args_plugins_msg_hdlr_t;

struct json_pluglet_args {
    const char *name;
    int32_t str_len;
    int jit;
};

plugins_t *plugins_manager = NULL;
int already_init = 0;

static char daemon_vty_dir[PATH_MAX]; // config folder of the protocol
static plugin_info_t *plugins_info; // insertion points for the protocol
static int max_plugin; // number of insertion points
pthread_t plugin_listener; // thread receiving pluglets from outside the main process
unsigned int finished = 0;

static int nb_plugins(plugin_info_t *info) {

    int count;
    int max = -1;
    for (count = 0; info[count].plugin_id != 0 && info[count].plugin_str != NULL; count++)
        if (info[count].plugin_id > max)
            max = info[count].plugin_id;
    return max;
}

static int is_directory(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0)
        return 0;
    return S_ISDIR(statbuf.st_mode);
}

static char *set_daemon_vty_dir(const char *path, size_t len) {
    size_t len_cpy = len > PATH_MAX ? PATH_MAX : len;

    memset(daemon_vty_dir, 0, PATH_MAX * sizeof(char));
    strncpy(daemon_vty_dir, path, len_cpy);
    return daemon_vty_dir;
}

static int set_plugins_info(plugin_info_t *pi_array) {

    if (!pi_array) return 1;

    plugins_info = pi_array;
    return 0;
}

plugin_info_t *get_plugin_info() {
    return plugins_info;
}

int get_max_plugins() {
    return max_plugin;
}

/* should be used in the protocol to "pluginize" */
int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *process_vty_dir, size_t len, plugin_info_t *plugins_array,
                    const char *monitoring_address, const char *monitoring_port, int require_monit) {

    int msqid;
    if (already_init) return 0;
    if (!process_vty_dir) return -1;

    set_daemon_vty_dir(process_vty_dir, len);
    if (set_plugins_info(plugins_array) != 0) return -1;
    max_plugin = nb_plugins(plugins_array);

    int i;
    if (plugins_manager) return 0; // already init, exit

    // start monitor server
    if (init_monitoring(monitoring_address, monitoring_port, require_monit) == -1) {
        return -1;
    }


    plugins_manager = malloc(sizeof(plugins_t));
    if (!plugins_manager) {
        perror("Cannot create plugin manager");
        return -1;
    }
    plugins_manager->size = 0;

    for (i = 0; i < MAX_PLUGINS; i++) {
        plugins_manager->ubpf_machines[i] = NULL;
    }

    if (init_ubpf_manager(api_proto) != 0) {
        fprintf(stderr, "Can't start ubpf manager\n");
        return -1;
    }

    args_plugins_msg_hdlr_t *msg_hdlr_args = malloc(sizeof(args_plugins_msg_hdlr_t));
    if (!msg_hdlr_args) {
        perror("Thread args malloc failure");
        return -1;
    }

    msqid = init_ubpf_inject_queue_rcv();
    msg_hdlr_args->msqid = msqid;

    if (msqid == -1) {
        fprintf(stderr, "Unable to start dynamic plugin injection\n");
        return -1;
    }

    if (pthread_create(&plugin_listener, NULL, &plugin_msg_handler, msg_hdlr_args) != 0) {
        fprintf(stderr, "Unable to create thread for dynamic plugin injection\n");
        return -1;
    }

    if (pthread_detach(plugin_listener) != 0) {
        fprintf(stderr, "Thread detachment failed (%s)", __func__);
        return -1;
    }

    already_init = 1;
    return 0;
}


void ubpf_terminate() {

    turnoff_monitoring();
    destroy_ubpf_manager();
    finished = 1;
    remove_xsi();
    free(plugins_manager);
    destroy_context();

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


static int str_plugin_to_int(const char *plugin_str) {
    int i;

    for (i = 0; plugins_info[i].plugin_id != 0 && plugins_info[i].plugin_str != NULL; i += 1) {
        if (strncmp(plugin_str, plugins_info[i].plugin_str, 50) == 0) {
            return plugins_info[i].plugin_id;
        }
    }
    return -1;
}

const char *id_plugin_to_str(unsigned int plugin_id) {
    int i;

    for (i = 0; plugins_info[i].plugin_id != 0 && plugins_info[i].plugin_str != NULL; i -= -1) {
        if (plugins_info[i].plugin_id == plugin_id) return plugins_info[i].plugin_str;
    }

    return "UNK";
}


static int json_pluglet_parse(json_object *pluglet, struct json_pluglet_args *info) {

    json_object *location;
    json_object *jit_obj;
    int32_t len;
    const char *bytecode_name;
    int jit;

    if (!info) return -1;

    if (!json_object_object_get_ex(pluglet, "path", &location)) return -1;

    bytecode_name = json_object_get_string(location);
    len = json_object_get_string_len(location);

    if (!json_object_object_get_ex(pluglet, "jit", &jit_obj)) jit = json_object_get_boolean(jit_obj);
    else jit = -1;

    info->jit = jit;
    info->name = bytecode_name;
    info->str_len = len;

    return 0;
}


int load_plugin_from_json(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir) {
    int plugin_id;
    int len;
    int pluglet_type;
    json_bool jit;
    json_bool jit_master;

    char *end_ptr;
    const char *str_override_location;
    const char *bytecode_name;
    char *master_sysconfdir = NULL;
    char *ptr_plug_dir; // points after the master_sysconfig string in the buffer
    unsigned int seq;
    char plug_dir[PATH_MAX];
    int32_t shared_mem;
    int32_t extra_mem;

    struct json_pluglet_args info;

    memset(plug_dir, 0, PATH_MAX * sizeof(char));

    json_object *plugins;
    json_object *main_obj = json_object_from_file(file_path);
    json_object *override_location;

    json_object *location;
    json_object *jit_obj;

    json_object *shared_mem_obj;
    json_object *extra_mem_obj;

    json_object *replace_pluglet;

    if (main_obj == NULL) return -1;

    if (!json_object_object_get_ex(main_obj, "plugins", &plugins)) {
        return -1; // malformed json
    }

    if (!json_object_object_get_ex(main_obj, "dir", &override_location)) {
        strncpy(plug_dir, sysconfdir, len_arg_sysconfdir);
        master_sysconfdir = plug_dir;
        ptr_plug_dir = master_sysconfdir + len_arg_sysconfdir;
    } else {
        len = json_object_get_string_len(override_location);
        str_override_location = json_object_get_string(override_location);

        if (len > PATH_MAX) return -1;

        if (access(str_override_location, X_OK) != 0) {
            perror("Folder access");
            return -1;
        }
        if (!is_directory(str_override_location)) {
            fprintf(stdout, "Not a directory\n");
            return -1;
        }
        strncpy(plug_dir, str_override_location, len);
        master_sysconfdir = plug_dir;
        ptr_plug_dir = master_sysconfdir + len;
    }

    if (*ptr_plug_dir != '/') {
        *ptr_plug_dir = '/';
        ptr_plug_dir += 1;
    }

    if (json_object_object_get_ex(main_obj, "jit_all", &jit_obj)) jit_master = json_object_get_boolean(jit_obj);
    else jit_master = 0;


    json_object_object_foreach(plugins, plugin_str, curr_plugin) {
        plugin_id = str_plugin_to_int(plugin_str);
        if (plugin_id == -1) continue;

        json_object_object_foreach(curr_plugin, hook, pluglets) {
            pluglet_type = strncmp(hook, "pre", 3) == 0 ? BPF_PRE :
                           strncmp(hook, "post", 4) == 0 ? BPF_POST :
                           strncmp(hook, "replace", 6) == 0 ? BPF_REPLACE : -1;

            if (json_object_object_get_ex(curr_plugin, "extra_mem", &extra_mem_obj))
                extra_mem = json_object_get_int(extra_mem_obj);
            else extra_mem = 0;


            if (json_object_object_get_ex(curr_plugin, "shared_mem", &shared_mem_obj))
                shared_mem = json_object_get_int(shared_mem_obj);
            else shared_mem = 0;

            if (pluglet_type != -1) {

                if (BPF_REPLACE == pluglet_type) {

                    memset(&info, 0, sizeof(info));
                    if (json_pluglet_parse(pluglets, &info) != 0) continue;
                    strncpy(ptr_plug_dir, info.name, info.str_len);
                    ptr_plug_dir[info.str_len] = 0;

                    jit = info.jit == -1 ? jit_master : info.jit;

                    if (add_pluglet(master_sysconfdir, extra_mem, shared_mem, plugin_id, pluglet_type, 0, jit) == -1) {
                        ubpf_log(INSERTION_ERROR, plugin_id, pluglet_type, 0, "Startup");
                    }
                } else {
                    json_object_object_foreach(pluglets, seq_str, pluglet) {

                        seq = strtoul(seq_str, &end_ptr, 10);
                        if (*end_ptr != 0) continue;

                        memset(&info, 0, sizeof(info));
                        if (json_pluglet_parse(pluglet, &info) != 0) continue;
                        strncpy(ptr_plug_dir, info.name, info.str_len);
                        ptr_plug_dir[info.str_len] = 0;

                        jit = info.jit == -1 ? jit_master : info.jit;

                        if (add_pluglet(master_sysconfdir, extra_mem, shared_mem, plugin_id, pluglet_type, seq, jit) ==
                            -1) {
                            ubpf_log(INSERTION_ERROR, plugin_id, pluglet_type, seq, "Startup");
                        }
                    }
                }
            }
        }
    }

    json_object_put(main_obj);

    return 0;
}

int is_volatile_plugin(int plug_ID) {

    return plug_ID > max_plugin;
}

static int
__add_pluglet_generic(const void *generic_ptr, int id_plugin, int type_plug, int type_ptr,
                      size_t len, size_t add_mem_len, size_t shared_mem, uint32_t seq, uint8_t jit,
                      const char **err) {

    plugin_t *plugin_ptr;
    plugin_t *plugin;
    const void *bytecode;
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
            bytecode = generic_ptr;
            bytecode_len = len;
            break;
        default:
            *err = "Pointer passed to add_plugin not recognized";
            return -1;
    }


    switch (type_plug) {
        case BPF_PRE:
            if (add_pre_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_POST:
            if (add_post_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
                *err = "Bytecode insertion failed";
                return -1;
            }
            break;
        case BPF_REPLACE:
            if (add_replace_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
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

int __add_pluglet_ptr(const uint8_t *bytecode, int id_plugin, int type_plugin, size_t len,
                      size_t add_mem_len, size_t shared_mem, uint32_t seq, uint8_t jit,
                      const char **err) {
    return __add_pluglet_generic(bytecode, id_plugin, type_plugin, ADD_TYPE_OWNPTR, len, add_mem_len, shared_mem,
                                 seq, jit, err);
}

int __add_pluglet(const char *path_code, int id_plugin, int type_plugin, size_t add_mem_len, size_t shared_mem,
                  uint32_t seq, uint8_t jit, const char **err) {
    return __add_pluglet_generic(path_code, id_plugin, type_plugin, ADD_TYPE_FILE, 0, add_mem_len, shared_mem,
                                 seq, jit, err);
}

int add_pluglet(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_plugglet,
                uint32_t seq, uint8_t jit) {
    const char *err;
    if (__add_pluglet(path_code, id_plugin, type_plugglet, add_mem_len, shared_mem, seq, jit, &err) == -1) {
        fprintf(stderr, "%s\n", err);
        return -1;
    }
    return 0;
}


int rm_plugin(int id_plugin, const char **err) {

    plugin_t *ptr_plugin;

    if (id_plugin <= 0 || id_plugin > MAX_PLUGINS) {
        if (err) *err = PLUGIN_RM_ERROR_ID_NEG;
        return -1;
    }

    if (!is_id_in_use(id_plugin)) {
        if (err) *err = PLUGIN_RM_ERROR_404;
        return -1;
    }

    ptr_plugin = plugins_manager->ubpf_machines[id_plugin];

    if (ptr_plugin == NULL) {
        if (err) *err = PLUGIN_RM_ERROR_404;
        return -1;
    }
    destroy_plugin(ptr_plugin);
    plugins_manager->ubpf_machines[id_plugin] = NULL;

    plugins_manager->size--;
    if (err) *err = NULL;

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
        default:
            fprintf(stderr, "Plugin type not recognized\n");
            return 0;
    }

    if (ret_val) {
        *ret_val = return_value;
        /*if(*ret_val == EXIT_FAILURE)
            fprintf(stderr, "plugin execution encountered an error %s\n", id_plugin_to_str(plug_id));*/
    }

    if (exec_ok != 0) {
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

int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val) {

    plugin_t *pptr;

    if (plugin_id <= 0 || plugin_id > MAX_PLUGINS) return 0;

    pptr = plugins_manager->ubpf_machines[plugin_id];
    if (!pptr) return 0;

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
    // queue must be created before (and thus the "pluginized proto" must be running) !
    return init_ubpf_inject_queue(1);
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

    key = ftok(daemon_vty_dir, E_BPF_QUEUE_KEY);
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

    key = ftok(daemon_vty_dir, E_BPF_SHMEM_KEY);

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

    key = ftok(daemon_vty_dir, E_BPF_SHMEM_KEY);
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

    free(args);

    while (!finished) { // TODO additional memory in CLI (static now) see __add_plugin_ptr calls -> dynamic or static ?
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
                if (__add_pluglet_ptr(data_ptr, rcvd_msg.location, rcvd_msg.plugin_type,
                                      rcvd_msg.length, 0, 0, rcvd_msg.after, rcvd_msg.jit, &str_err) <
                    0) {
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
                        __add_pluglet_ptr(data_ptr, rcvd_msg.location, rcvd_msg.plugin_type,
                                          rcvd_msg.length, 0, 0, rcvd_msg.after, rcvd_msg.jit, &str_err) <
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
    return 0;
}

void remove_xsi() {

    int msqid, memid;
    key_t msqkey, memkey;

    msqkey = ftok(daemon_vty_dir, E_BPF_QUEUE_KEY);
    if (msqkey == -1) {
        perror("Can't generate key");
    }
    memkey = ftok(daemon_vty_dir, E_BPF_SHMEM_KEY);
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