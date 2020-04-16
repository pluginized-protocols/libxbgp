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
#include <errno.h>
#include "ubpf_manager.h"
#include "map.h"
#include "bpf_plugin.h"
#include "ubpf_api.h"
#include "monitoring_server.h"
#include "ubpf_context.h"

#include <stdio.h>

#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#define ADD_TYPE_OWNPTR 1
#define ADD_TYPE_FILE 2

#define QUEUEID "queue.id"
#define SHAREDID "shared.id"

static void *plugin_msg_handler(void *args);

typedef struct args_plugin_msg_handler {
    int msqid;
    int shm_fd;
} args_plugins_msg_hdlr_t;

struct json_pluglet_args {
    const char *name;
    int32_t str_len;
    int jit;
};

plugins_t *plugins_manager = NULL;
int already_init = 0;

static char daemon_vty_dir[PATH_MAX]; // var state folder of the protocol
static plugin_info_t *plugins_info; // insertion points for the protocol
static int max_plugin; // number of insertion points
pthread_t plugin_listener; // thread receiving pluglets from outside the main process
unsigned int finished = 0;
static int msqid_listener = -1;
static char shm_plugin_name[NAME_MAX];
static uint8_t *mmap_shared_ptr;

static int
lambda_add_pluglet(const char *name_plugin, const char *path_plugin,
                   size_t extra_mem, size_t sh_mem, int plugin_id,
                   int pluglet_type, uint32_t seq, uint8_t jit);

static inline int full_write(int fd, const char *buf, size_t len) {

    ssize_t s;
    size_t total;

    total = 0;
    while (total < len) {
        s = write(fd, buf + total, len - total);
        if (s == 0 || s == -1) return -1;
        total += s;
    }
    return 0;
}

static unsigned int nb_plugins(plugin_info_t *info) {

    int count;
    short init = 0;
    unsigned int max = 0;

    for (count = 0; info[count].plugin_id != 0 && info[count].plugin_str != NULL; count++)
        if (!init) {
            max = info[count].plugin_id;
            init = 1;
        } else if (info[count].plugin_id > max)
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

int get_msqid() {
    return msqid_listener;
}

static inline int write_id(const char *folder, int msg_queue_id, const char *shm_id) {
    // write the random string AND the message queue ID
    int fd_shared, fd_msgqueue;
    char path[PATH_MAX], path2[PATH_MAX], r_path[PATH_MAX];
    int nb_char;
    char buf[10];

    memset(path, 0, sizeof(char) * PATH_MAX);
    memset(path2, 0, sizeof(char) * PATH_MAX);

    snprintf(path, PATH_MAX, "%s/%s", folder, QUEUEID);
    snprintf(path2, PATH_MAX, "%s/%s", folder, SHAREDID);
    memset(r_path, 0, sizeof(char) * PATH_MAX);
    realpath(path, r_path);
    fd_msgqueue = open(r_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);

    if (fd_msgqueue == -1) {
        perror("Can't create queue.id");
        return -1;
    }
    memset(r_path, 0, sizeof(char) * PATH_MAX);
    realpath(path2, r_path);
    fd_shared = open(r_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);

    if (fd_shared == -1) {
        perror("Can't create shared.id");
        return -1;
    }

    memset(buf, 0, 10);
    nb_char = snprintf(buf, 10, "%d", msg_queue_id);

    if (full_write(fd_msgqueue, buf, nb_char) == -1) {
        perror("Can't write to queue.id");
        return -1;
    }
    if (full_write(fd_shared, shm_id, NAME_MAX) == -1) {
        perror("Can't write to shared.id");
        return -1;
    }

    close(fd_msgqueue);
    close(fd_shared);
    return 0;
}

/* should be used in the protocol to "pluginize" */
int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *process_vty_dir, size_t len, plugin_info_t *plugins_array,
                    const char *monitoring_address, const char *monitoring_port, int require_monit) {

    int msqid, fd_shmem;
    if (already_init) return 0;
    if (!process_vty_dir) return -1;

    set_daemon_vty_dir(process_vty_dir, len);
    if (set_plugins_info(plugins_array) != 0) return -1;
    max_plugin = nb_plugins(plugins_array);
    memset(shm_plugin_name, 0, NAME_MAX);

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

    msqid = init_ubpf_inject_queue();

    if (msqid == -1) {
        perror("Unable to create kernel queue");
        return -1;
    }

    fd_shmem = init_shared_memory(shm_plugin_name);

    if (fd_shmem == -1) {
        perror("File descriptor (shared memory) initialisation failed");
        return -1;
    }

    msg_hdlr_args->msqid = msqid;
    msg_hdlr_args->shm_fd = fd_shmem;

    if (pthread_create(&plugin_listener, NULL, &plugin_msg_handler, msg_hdlr_args) != 0) {
        fprintf(stderr, "Unable to create thread for dynamic plugin injection\n");
        return -1;
    }

    if (pthread_detach(plugin_listener) != 0) {
        fprintf(stderr, "Thread detachment failed (%s)", __func__);
        return -1;
    }

    if (write_id(process_vty_dir, msqid, shm_plugin_name) == -1) {
        fprintf(stderr, "Write failed\n");
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
    plugins_manager = NULL;
    already_init = 0;
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


int str_plugin_to_int(const char *plugin_str) {
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

    if (json_object_object_get_ex(pluglet, "jit", &jit_obj)) jit = json_object_get_boolean(jit_obj);
    else jit = -1;

    info->jit = jit;
    info->name = bytecode_name;
    info->str_len = len;

    return 0;
}

/*
 * If syconfdir is NULL, the path must be filled in the JSON file
 */
int load_plugin_from_json_fn(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir, new_plug fn) {
    int plugin_id;
    int len;
    int pluglet_type;
    json_bool jit;
    json_bool jit_master;

    char *end_ptr;
    const char *str_override_location;
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

    json_object *jit_obj;

    json_object *shared_mem_obj;
    json_object *extra_mem_obj;

    if (main_obj == NULL) {
        return -1;
    }

    if (!json_object_object_get_ex(main_obj, "plugins", &plugins)) {
        return -1; // malformed json
    }

    if (json_object_object_length(plugins) == 0) {
        // there is maybe a problem
        fprintf(stderr, "[WARNING] no announced plugins\n");
    }

    if (!json_object_object_get_ex(main_obj, "dir", &override_location)) {
        if (sysconfdir == NULL) return -1;
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

    // refactor (foreach macro doesn't seem to work on FRRouting.................)
    struct json_object_iterator it_plugins;
    struct json_object_iterator it_plugins_end;

    it_plugins = json_object_iter_begin(plugins);
    it_plugins_end = json_object_iter_end(plugins);

    while (!json_object_iter_equal(&it_plugins, &it_plugins_end)) {

        const char *plugin_str = json_object_iter_peek_name(&it_plugins);
        struct json_object *curr_plugin = json_object_iter_peek_value(&it_plugins);

        plugin_id = str_plugin_to_int(plugin_str);
        if (plugin_id == -1) {
            json_object_iter_next(&it_plugins);
            continue;
        };

        struct json_object_iterator it_curr_plugin;
        struct json_object_iterator it_curr_plugin_end;

        it_curr_plugin = json_object_iter_begin(curr_plugin);
        it_curr_plugin_end = json_object_iter_end(curr_plugin);

        while (!json_object_iter_equal(&it_curr_plugin, &it_curr_plugin_end)) {

            const char *hook = json_object_iter_peek_name(&it_curr_plugin);
            struct json_object *pluglets = json_object_iter_peek_value(&it_curr_plugin);

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
                    if (json_pluglet_parse(pluglets, &info) != 0) {
                        json_object_iter_next(&it_curr_plugin);
                        continue;
                    }
                    strncpy(ptr_plug_dir, info.name, info.str_len);
                    ptr_plug_dir[info.str_len] = 0;

                    jit = info.jit == -1 ? jit_master : info.jit;

                    if (fn(NULL, master_sysconfdir, extra_mem, shared_mem, plugin_id, pluglet_type, 0, jit) != 0) {
                        ubpf_log(INSERTION_ERROR, plugin_id, pluglet_type, 0, "Startup");
                    }
                } else {
                    struct json_object_iterator it_curr_pluglet;
                    struct json_object_iterator it_curr_pluglet_end;

                    it_curr_pluglet = json_object_iter_begin(pluglets);
                    it_curr_pluglet_end = json_object_iter_end(pluglets);

                    while (!json_object_iter_equal(&it_curr_pluglet, &it_curr_pluglet_end)) {

                        const char *seq_str = json_object_iter_peek_name(&it_curr_pluglet);
                        struct json_object *pluglet = json_object_iter_peek_value(&it_curr_pluglet);

                        seq = strtoul(seq_str, &end_ptr, 10);
                        if (*end_ptr != 0) {
                            json_object_iter_next(&it_curr_pluglet);
                            continue;
                        }

                        memset(&info, 0, sizeof(info));
                        if (json_pluglet_parse(pluglet, &info) != 0) {
                            json_object_iter_next(&it_curr_pluglet);
                            continue;
                        }
                        strncpy(ptr_plug_dir, info.name, info.str_len);
                        ptr_plug_dir[info.str_len] = 0;

                        jit = info.jit == -1 ? jit_master : info.jit;

                        if (fn(NULL, master_sysconfdir, extra_mem, shared_mem, plugin_id, pluglet_type, seq, jit) !=
                            0) {
                            ubpf_log(INSERTION_ERROR, plugin_id, pluglet_type, seq, "Startup");
                        }

                        json_object_iter_next(&it_curr_pluglet);
                    }
                }
            }
            json_object_iter_next(&it_curr_plugin);
        }
        json_object_iter_next(&it_plugins);
    }

    json_object_put(main_obj);

    return 0;
}

int load_plugin_from_json(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir) {
    return load_plugin_from_json_fn(file_path, sysconfdir, len_arg_sysconfdir, lambda_add_pluglet);
}

int is_volatile_plugin(int plug_ID) {

    return plug_ID >= max_plugin;
}

static int
__add_pluglet_generic(const void *generic_ptr, int id_plugin, int type_plug, int type_ptr,
                      size_t len, size_t add_mem_len, size_t shared_mem, uint32_t seq, uint8_t jit,
                      int *err) {

    plugin_t *plugin_ptr;
    plugin_t *plugin;
    const void *bytecode;
    size_t bytecode_len;

    if (!err) {
        fprintf(stderr, "err must not be NULL\n");
        return -1;
    }

    if (id_plugin <= 0 || id_plugin >= MAX_PLUGINS) {
        *err = STATUS_MSG_PLUGIN_ID_IS_NEGATIVE;
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
                *err = STATUS_MSG_MEMALLOC_ERR;
                return -1;
            }
            break;
        case ADD_TYPE_OWNPTR:
            bytecode = generic_ptr;
            bytecode_len = len;
            break;
        default:
            *err = STATUS_MSG_INTERNAL_ERROR;
            return -1;
    }


    switch (type_plug) {
        case BPF_PRE:
            if (add_pre_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
                *err = STATUS_MSG_PLUGLET_INSERT_FAIL;
                return -1;
            }
            break;
        case BPF_POST:
            if (add_post_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
                *err = STATUS_MSG_PLUGLET_INSERT_FAIL;
                return -1;
            }
            break;
        case BPF_REPLACE:
            if (add_replace_function(plugin, bytecode, bytecode_len, seq, jit) != 0) {
                *err = STATUS_MSG_PLUGLET_INSERT_FAIL;
                return -1;
            }
            break;
        default:
            *err = STATUS_MSG_PLUGLET_ANCHOR_NOT_RECOGNISED;
            return -1;
    }

    if (type_ptr == ADD_TYPE_FILE) free((void *) bytecode);

    return 0;

}

int __add_pluglet_ptr(const uint8_t *bytecode, int id_plugin, int type_plugin, size_t len,
                      size_t add_mem_len, size_t shared_mem, uint32_t seq, uint8_t jit,
                      int *err) {
    return __add_pluglet_generic(bytecode, id_plugin, type_plugin, ADD_TYPE_OWNPTR, len, add_mem_len, shared_mem,
                                 seq, jit, err);
}

int __add_pluglet(const char *path_code, int id_plugin, int type_plugin, size_t add_mem_len, size_t shared_mem,
                  uint32_t seq, uint8_t jit, int *err) {
    return __add_pluglet_generic(path_code, id_plugin, type_plugin, ADD_TYPE_FILE, 0, add_mem_len, shared_mem,
                                 seq, jit, err);
}

int add_pluglet(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_pluglet,
                uint32_t seq, uint8_t jit) {
    int err = -1;
    if (__add_pluglet(path_code, id_plugin, type_pluglet, add_mem_len, shared_mem, seq, jit, &err) == -1) {
        fprintf(stderr, "Error -> %d\n", err);
        return -1;
    }
    return 0;
}

static int
lambda_add_pluglet(const char *name_plugin, const char *path_plugin,
                   size_t extra_mem, size_t sh_mem, int plugin_id,
                   int pluglet_type, uint32_t seq, uint8_t jit) {
    ((void) name_plugin);
    int err = -1;
    if (__add_pluglet(path_plugin, plugin_id, pluglet_type, extra_mem, sh_mem,
                      seq, jit, &err) == -1) {
        return err;
    };
    return STATUS_MSG_OK;
}

int rm_pluglet(int plugin_id, int seq, int anchor) {

    plugin_t *p;
    int status;
    if (plugin_id >= get_max_plugins()) return -1;

    p = plugins_manager->ubpf_machines[plugin_id];

    switch (anchor) {
        case BPF_PRE:
            status = rm_pre_function(p, seq);
            break;
        case BPF_REPLACE:
            status = rm_replace_function(p, seq);
            break;
        case BPF_POST:
            status = rm_post_function(p, seq);
            break;
        default:
            return -1;
    }

    return status == 0 ? 0 : -1;
}

int rm_plugin(int id_plugin, int *err) {

    plugin_t *ptr_plugin;

    if (id_plugin <= 0 || id_plugin > MAX_PLUGINS) {
        if (err) *err = STATUS_MSG_RM_ERROR_ID_NEGATIVE;
        return -1;
    }

    if (!is_id_in_use(id_plugin)) {
        if (err) *err = STATUS_MSG_RM_ERROR_NOT_FOUND;
        return -1;
    }

    ptr_plugin = plugins_manager->ubpf_machines[id_plugin];

    if (ptr_plugin == NULL) {
        if (err) *err = STATUS_MSG_RM_ERROR_NOT_FOUND;
        return -1;
    }
    destroy_plugin(ptr_plugin);
    plugins_manager->ubpf_machines[id_plugin] = NULL;

    plugins_manager->size--;
    if (err) *err = STATUS_MSG_OK;

    return 0;

}

static inline int
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

int init_ubpf_inject_queue() {
    int msqid;
    int curr_errno;
    int r;
    key_t key;
    struct timespec ts;

    if (timespec_get(&ts, TIME_UTC) == 0) {
        perror("TimeSpec");
        return -1;
    }
    srandom(ts.tv_nsec ^ ts.tv_sec);  /* Seed the PRNG */

    do {
        r = (int) random();
        key = ftok(daemon_vty_dir, r);
        msqid = msgget(key, 0600u | IPC_CREAT | IPC_EXCL);
        curr_errno = errno;
        if (msqid < 0) {
            if (curr_errno != EEXIST) {
                perror("Unable to create the queue");
                return -1;
            }
        }
    } while (curr_errno == EEXIST && msqid < 0);

    msqid_listener = msqid;
    return msqid;
}

static inline int generate_random_string(char *buffer, size_t len_buffer) {

    struct timespec ts;
    size_t i;
    char curr_char;
    long super_random;

    if (timespec_get(&ts, TIME_UTC) == 0) return -1;
    srandom(ts.tv_nsec ^ ts.tv_sec);  /* Seed the PRNG */

    for (i = 0; i < len_buffer; i++) {

        super_random = random() % 63; // distribution to be weighted to the size of the intervals
        if (super_random <= 25) {
            curr_char = (char) ((random() % ('z' - 'a' + 1)) + 'a');
        } else if (super_random <= 52) {
            curr_char = (char) ((random() % ('Z' - 'A' + 1)) + 'A');
        } else {
            curr_char = (char) ((random() % ('9' - '0' + 1)) + '0');
        }

        buffer[i] = curr_char;
    }

    return 0;
}

int init_shared_memory(char *shared_mem_name) { // shared_mem_name MUST be of size NAME_MAX
    int oflag, fd;
    int must_cont;
    char *rnd_name;
    char name[NAME_MAX];
    mode_t mode;
    *name = '/';

    uint8_t *data_ptr;

    rnd_name = name + 1;
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP; // rw-rw----
    oflag = O_RDWR | O_CREAT | O_EXCL;

    do {
        memset(rnd_name, 0, NAME_MAX - 1);
        if (generate_random_string(rnd_name, NAME_MAX - 2) != 0) return -1;
        rnd_name[NAME_MAX - 2] = 0;
        fd = shm_open(name, oflag, mode);
        if (fd < 0) {
            if (errno == EEXIST) must_cont = 1;
            else return -1;
        } else must_cont = 0;
    } while (must_cont);

    data_ptr = mmap(NULL, MAX_SIZE_PLUGIN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data_ptr == (void *) -1) {
        perror("MMAP initialization failed");
        return -1;
    }

    mmap_shared_ptr = data_ptr;

    strncpy(shared_mem_name, name, NAME_MAX);
    return fd;
}

int close_shared_memory() {

    if (munmap(mmap_shared_ptr, MAX_SIZE_PLUGIN) != 0) {
        perror("Unable to detach shared memory");
    }

    return shm_unlink(shm_plugin_name);
}

static inline __off_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        perror("Can't retrieve stats for file");
        return -1;
    }
    return st.st_size;
}

int send_pluglet(const char *path, const char *plugin_name, short jit, int hook, unsigned int action,
                 uint16_t extra_mem, uint16_t shared_mem, uint32_t seq, int msqid, int shared_fd) {

    ubpf_queue_msg_t msg;
    __off_t size;
    size_t len;

    char rel_path[PATH_MAX];
    int plug_id;

    plug_id = str_plugin_to_int(plugin_name);
    if (plug_id == -1) return -1;

    if (path) {
        realpath(path, rel_path);

        if (access(rel_path, R_OK) == -1) {
            perror("Read attribute missing to the file");
            return -1; // Can't read ubpf file
        }
    } else if (action != E_BPF_ADD && action != E_BPF_REPLACE &&
               action != E_BPF_RM && action != E_BPF_TRANSACTION_ADD) { // check if action is not add or replace
        fprintf(stderr, "Bad action\n");
        return -1;
    }

    size = file_size(path);
    if (size == -1) return -1;

    if ((len = store_plugin((size_t) size, path, shared_fd)) == 0) {
        return -1;
    }

    assert(len == (size_t) size && "Read length vs actual size differ in size");

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = action;
    msg.jit = jit;
    msg.hook = hook;
    msg.seq = hook == BPF_REPLACE ? 0 : seq;
    msg.extra_memory = extra_mem;
    msg.shared_memory = shared_mem;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Plugin send error [msgsnd]");
        return -1;
    }

    return 0;
}


int send_rm_plugin(int msqid, const char *plugin_name) {

    ubpf_queue_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_RM;
    strncpy(msg.plugin_name, plugin_name, NAME_MAX);

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Plugin send error [msgsnd]");
        return -1;
    }

    return 0;
}

int send_rm_pluglet(int msqid, const char *plugin_name, uint32_t seq, int anchor) {

    ubpf_queue_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_RM_PLUGLET;
    strncpy(msg.plugin_name, plugin_name, NAME_MAX);
    msg.seq = seq;
    msg.hook = anchor;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Message send error [msgsnd]");
        return -1;
    }

    return 0;
}

int send_begin_transaction(int msqid) {
    ubpf_queue_msg_t msg;
    ubpf_queue_info_msg_t from_ebpf;
    memset(&msg, 0, sizeof(msg));

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_TRANSACTION_BEGIN;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Error while sending message");
        return -1;
    }

    if (msgrcv(msqid, &from_ebpf, sizeof(ubpf_queue_info_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
        perror("Unable to get a response from");
    }

    if (from_ebpf.status != STATUS_MSG_OK) return -1;

    return 0;
}

int send_finish_transaction(int msqid) {
    ubpf_queue_msg_t msg;
    ubpf_queue_info_msg_t from_ebpf;
    memset(&msg, 0, sizeof(msg));

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_TRANSACTION_END;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Error while sending message");
        return -1;
    }

    if (msgrcv(msqid, &from_ebpf, sizeof(ubpf_queue_info_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
        perror("Unable to get a response from");
    }

    if (from_ebpf.status != STATUS_MSG_OK) return -1;
    return 0;
}


size_t store_plugin(size_t size, const char *path, int shared_fd) {

    uint8_t *data;
    size_t plugin_length;

    data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);

    if (data == (void *) -1) {
        perror("Can't attach shared memory");
    }

    memset(data, 0, size);

    if (!readfileOwnPtr(path, MAX_SIZE_PLUGIN, &plugin_length, data)) {
        fprintf(stderr, "Cannot read bytecode\n");
        return 0;
    }

    munmap(data, size);

    return plugin_length;
}

static void *plugin_msg_handler(void *args) {

    ubpf_queue_info_msg_t info;
    args_plugins_msg_hdlr_t *cast_args = args;

    int err = 0;
    int internal_err = 0;
    int plugin_id;
    int mysqid;

    int transaction_begin = 0;

    info.mtype = MTYPE_INFO_MSG;

    if (!args) {
        fprintf(stderr, "No kernel queue ID received, EXITING...\n");
        exit(EXIT_FAILURE);
    }

    mysqid = cast_args->msqid;
    // fd = cast_args->shm_fd;
    ubpf_queue_msg_t rcvd_msg;

    free(args);

    while (!finished) {
        err = internal_err = 0;
        memset(&rcvd_msg, 0, sizeof(ubpf_queue_msg_t));

        if (msgrcv(mysqid, &rcvd_msg, sizeof(ubpf_queue_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
            continue;
        }

        if (msync(mmap_shared_ptr, MAX_SIZE_PLUGIN, MS_SYNC) != 0) return NULL;

        switch (rcvd_msg.hook) {
            case BPF_PRE:
            case BPF_POST:
            case BPF_REPLACE:
                break;
            default:
                fprintf(stderr, "Unrecognized plugin anchor/hook\n");
                err = 1;
                goto end;
        }

        plugin_id = str_plugin_to_int(rcvd_msg.plugin_name);
        if (plugin_id == -1) continue;

        switch (rcvd_msg.plugin_action) {
            case E_BPF_REPLACE:
            case E_BPF_ADD:
                if (__add_pluglet_ptr(mmap_shared_ptr, plugin_id, rcvd_msg.hook, rcvd_msg.bytecode_length,
                                      rcvd_msg.extra_memory, rcvd_msg.shared_memory, rcvd_msg.seq,
                                      rcvd_msg.jit, &internal_err) < 0) {
                    err = 1;
                    info.status = internal_err;
                }
                break;
            case E_BPF_RM:
                if (rm_plugin(plugin_id, &internal_err) == -1) {
                    err = 1;
                    info.status = internal_err;
                }
                break;
            case E_BPF_RM_PLUGLET:
                if (rm_pluglet(plugin_id, rcvd_msg.seq, rcvd_msg.hook)) {
                    err = 1;
                    info.status = STATUS_MSG_PLUGLET_RM_FAIL;
                }
                break;
            case E_BPF_TRANSACTION_BEGIN:
                if (transaction_begin > 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_IN_PROGRESS;
                } else {
                    transaction_begin = 1;
                }
                break;
            case E_BPF_TRANSACTION_ADD:
                if (transaction_begin == 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_NOT_BEGIN;
                } else if (__add_pluglet_ptr(mmap_shared_ptr, plugin_id, rcvd_msg.hook, rcvd_msg.bytecode_length,
                                             rcvd_msg.extra_memory, rcvd_msg.shared_memory,
                                             rcvd_msg.seq, rcvd_msg.jit, &internal_err) < 0) {
                    err = 1;
                    info.status = internal_err;
                } else {
                    // OK !
                }
                break;
            case E_BPF_TRANSACTION_END:
                if (transaction_begin == 0) {
                    err = 1;
                    info.status = STATUS_MSG_NO_TRANSACTION;
                } else if (commit_transaction(plugins_manager->ubpf_machines[plugin_id]) != 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_FAIL;
                }
                transaction_begin = 0;
                break;
            default:
                fprintf(stderr, "Unrecognised msg type (%s)\n", __func__);
                break;
        }

        end:

        if (!err) {
            info.status = STATUS_MSG_OK;
        }

        if (msgsnd(mysqid, &info, sizeof(ubpf_queue_info_msg_t), 0) != 0) {
            perror("Can't send confirmation message to the ");
        }

    }
    return 0;
}

void remove_xsi() {

    size_t i, size;
    char r_path[PATH_MAX], conc_path[PATH_MAX];

    if (msgctl(msqid_listener, IPC_RMID, NULL) == -1) {
        perror("Can't remove message queue");
    }
    close_shared_memory();

    // unlink files
    const char *t[] = {QUEUEID, SHAREDID};
    size = sizeof(t) / sizeof(t[0]);
    for (i = 0; i < size; i++) {
        memset(r_path, 0, PATH_MAX * sizeof(char));
        memset(conc_path, 0, PATH_MAX * sizeof(char));
        snprintf(conc_path, PATH_MAX - 1, "%s/%s", daemon_vty_dir, t[i]);
        realpath(conc_path, r_path);
        if (unlink(r_path) != 0) {
            perror("Unlink failed");
        }
    }
    //
    rm_ipc();
}