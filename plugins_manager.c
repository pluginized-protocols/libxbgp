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

static int is_init = 0;
static manager_t master;


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

/* used when an insertion point is deleted. */
static void on_delete_vm(void *self) {
    vm_container_t *vm = self;
    vm_container_t *table = master.vms_table;

    if (!table) {
        return;
    }

    HASH_DELETE(hh, table, vm);
    master.vms_table = table;
}

//static int is_directory(const char *path) {
//    struct stat statbuf;
//    if (stat(path, &statbuf) != 0)
//        return 0;
//    return S_ISDIR(statbuf.st_mode);
//}

/* should be used in the protocol to "pluginize" */
int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *var_state_dir, size_t len,
                    insertion_point_info_t *insertion_points_array,
                    const char *monitoring_address, const char *monitoring_port, int require_monit) {

    if (is_init) return 0;
    if (!var_state_dir) return -1;

    memset(&master, 0, sizeof(master));
    strncpy(master.var_state_path, var_state_dir, len);
    master.point_info = insertion_points_array;
    master.helper_functions = api_proto;

    // start monitor server
    if (monitoring_address && monitoring_port) {
        if (init_monitoring(monitoring_address, monitoring_port, require_monit) == -1) {
            return -1;
        }
    }
    // start plugin message listener
    // todo
    is_init = 1;
    return 0;
}

static void flush_manager(manager_t *manager) {

    insertion_point_t *point, *tmp_p;
    plugin_t *p, *tmp_plugin;
    vm_container_t *vm, *tmp_vm;

    HASH_ITER(hh, manager->insertion_point_table, point, tmp_p) {
        HASH_DELETE(hh, manager->insertion_point_table, point);
        free_insertion_point(point);
    }

    HASH_ITER(hh, manager->plugin_table, p, tmp_plugin) {
        HASH_DELETE(hh, manager->plugin_table, p);
        destroy_plugin(p);
    }

    HASH_ITER(hh, manager->vms_table, vm, tmp_vm) {
        HASH_DELETE(hh, manager->vms_table, vm);
        shutdown_vm(vm);
    }

    // pthread del TODO

}

void ubpf_terminate() {

    turnoff_monitoring();
    // off listener thread TODO

    flush_manager(&master);

}

int add_extension_code(const char *plugin_name, size_t plugin_name_len, uint64_t extra_mem, uint64_t shared_mem,
                       int insertion_point_id, const char *insertion_point, size_t i_pt_name, anchor_t type_anchor,
                       int seq_anchor, int jit,
                       const char *obj_path_code, const char *vm_name, size_t vm_name_len, proto_ext_fun_t *api_proto) {

    uint8_t *bytecode;
    size_t bytecode_len;
    vm_container_t *vm;
    plugin_t *p;
    insertion_point_t *point;

    /* 0. Read ELF/Obj file */
    bytecode = readfile(obj_path_code, MAX_SIZE_PLUGIN, &bytecode_len);

    /* 1. Get Plugin */

    p = get_plugin_by_name(&master, plugin_name);
    if (!p) {
        p = init_plugin(extra_mem, shared_mem, plugin_name, plugin_name_len);
        if (!p) return -1;
        if (register_plugin(&master, p) != 0) return -1;
    }

    /* 2. Get insertion point */ // todo check INSERTION POINT NAME !
    if (!insertion_point_is_registered_by_id(&master, insertion_point_id)) {
        point = new_insertion_point(insertion_point_id, insertion_point, i_pt_name);
        if (!point) return -1;
        if (register_insertion_point(&master, point) != 0) return -1;
    } else {
        point = get_insertion_point(&master, insertion_point_id);
    }

    /* 3. Build VM if not present */
    if (is_vm_registered_by_name(&master, vm_name)) {
        /* the vm is already here, must rebuild it */
        vm = unregister_vm(&master, vm_name);
        plugin_delete_vm(vm);
        rm_vm_insertion_point(vm);
        shutdown_vm(vm);
        vm = NULL;
    }

    vm = new_vm(type_anchor, seq_anchor, point, jit, vm_name, vm_name_len, p, bytecode, bytecode_len, api_proto,
                on_delete_vm);
    if (!vm) return -1;
    if (register_vm(&master, vm) != 0) return -1;

    /* 4. ADD VM to plugin */
    if (plugin_add_vm(p, vm) != 0) return -1;

    /* 5. And to the insertion point */
    if (add_vm_insertion_point(point, vm, type_anchor, seq_anchor) != 0) return -1;

    return 0;
}

int remove_extension_code(const char *name) {
    vm_container_t *vm;
    vm = unregister_vm(&master, name);
    if (!vm) return -1;

    /* delete code from insertion point */
    if (rm_vm_insertion_point(vm) != 0) return -1;

    /* delete code from plugin */
    if (plugin_delete_vm(vm) != 0) return -1;

    /* shutdown VM */
    shutdown_vm(vm);

    return 0;
}

int remove_plugin(const char *name) {
    return unregister_plugin(&master, name);
}

int remove_insertion_point(int id) {
    return unregister_insertion_point(&master, id);
}

inline int is_vm_registered(manager_t *manager, vm_container_t *vm) {
    vm_container_t *the_vm;
    HASH_FIND_STR(manager->vms_table, vm->vm_name, the_vm);

    return the_vm != NULL;
}

inline int is_vm_registered_by_name(manager_t *manager, const char *name) {
    vm_container_t *the_vm;
    HASH_FIND_STR(manager->vms_table, name, the_vm);

    return the_vm != NULL;
}

int register_vm(manager_t *manager, vm_container_t *vm) {
    if (is_vm_registered(manager, vm)) return -1;

    HASH_ADD_STR(manager->vms_table, vm_name, vm);
    return 0;
}

vm_container_t *unregister_vm(manager_t *manager, const char *name) {
    vm_container_t *vm;
    HASH_FIND_STR(manager->vms_table, name, vm);
    if (!vm) return NULL;

    HASH_DEL(manager->vms_table, vm);
    return vm;
}

inline insertion_point_t *get_insertion_point_by_id(manager_t *manager, int id) {

    insertion_point_t *point;
    HASH_FIND_INT(manager->insertion_point_table, &id, point);
    return point;

}

inline int is_plugin_registered(manager_t *manager, plugin_t *p) {
    plugin_t *the_plugin;
    HASH_FIND_STR(manager->plugin_table, p->name, the_plugin);
    return the_plugin != NULL;
}

inline plugin_t *get_plugin_by_name(manager_t *manager, const char *name) {
    plugin_t *the_plugin;
    HASH_FIND_STR(manager->plugin_table, name, the_plugin);
    return the_plugin;
}

inline int is_plugin_registered_by_name(manager_t *manager, const char *name) {
    return get_plugin_by_name(manager, name) != NULL;
}

int register_plugin(manager_t *manager, plugin_t *plugin) {
    if (is_plugin_registered(manager, plugin)) return -1;
    HASH_ADD_STR(manager->plugin_table, name, plugin);
    return 0;
}

int unregister_plugin(manager_t *manager, const char *name) {
    plugin_t *p;
    vm_container_t *vm;

    HASH_FIND_STR(manager->plugin_table, name, p);
    if (!p) return -1;

    HASH_DELETE(hh, manager->plugin_table, p);

    /* remove vm from master table since will be deallocated when destroying plugin */
    for (vm = p->vms; vm != NULL; vm = vm->hh_plugin.next) {
        HASH_DELETE(hh, manager->vms_table, vm);
    }

    destroy_plugin(p);
    return 0;
}

inline int insertion_point_is_registered(manager_t *manager, insertion_point_t *point) {

    insertion_point_t *the_point;

    HASH_FIND_INT(manager->insertion_point_table, &point->id, the_point);

    return the_point != NULL;
}

inline int insertion_point_is_registered_by_id(manager_t *manager, int id) {
    insertion_point_t *the_point;
    HASH_FIND_INT(manager->insertion_point_table, &id, the_point);

    return the_point != NULL;
}

int register_insertion_point(manager_t *manager, insertion_point_t *point) {
    if (!point) return -1;
    if (insertion_point_is_registered(manager, point)) return -1; // already registered
    HASH_ADD_INT(manager->insertion_point_table, id, point);
    return 0;
}

int unregister_insertion_point(manager_t *manager, int id) {

    insertion_point_t *point;
    insertrion_point_iterator_t it;
    vm_container_t *current_vm;
    HASH_FIND_INT(manager->insertion_point_table, &id, point);
    if (!point) return -1;

    HASH_DELETE(hh, manager->insertion_point_table, point);

    /* unregister VMs from master table */
    insertion_point_vm_iterator(point, &it);
    while (insertion_point_vm_iterator_hasnext(&it)) {
        current_vm = insertion_point_vm_iterator_next(&it);
        HASH_DELETE(hh, manager->vms_table, current_vm);
    }

    free_insertion_point(point);

    return 0;
}


int str_insertion_point_to_int(manager_t *manager, const char *plugin_str) {
    insertion_point_t *point, *tmp;
    /* the hashing is based on the integer ID, need to browse the whole hash-table */
    HASH_ITER(hh, manager->insertion_point_table, point, tmp) {
        if (strncmp(point->name, plugin_str, 256) == 0) return point->id;
    }

    return -1;
}

const char *id_insertion_point_to_str(manager_t *manager, int id) {
    insertion_point_t *point;

    point = get_insertion_point(manager, id);
    if (!point) return "UNK";

    return point->name;
}

inline insertion_point_t *get_insertion_point(manager_t *manager, int id) {
    insertion_point_t *point;
    if (!manager) return NULL;
    HASH_FIND_INT(manager->insertion_point_table, &id, point);
    return point;
}

inline insertion_point_t *insertion_point(int id) {
    return get_insertion_point(&master, id);
}

void *readfile(const char *path, size_t maxlen, size_t *len) {

    uint8_t *data;
    char absolute_path[PATH_MAX];
    const char *sel_path;

    FILE *file;
    if (!strcmp(path, "-")) {
        file = stdin; //fdopen(STDIN_FILENO, "r");
        sel_path = path;
    } else {
        memset(absolute_path, 0, PATH_MAX * sizeof(char));
        realpath(path, absolute_path);
        sel_path = absolute_path;
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s (uid %u)\n", sel_path, strerror(errno), getuid());
        return NULL;
    }

    data = calloc(maxlen, 1);
    if (!data) {
        perror("mem alloc failed");
        return NULL;
    }

    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", sel_path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                sel_path, (unsigned) maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;

}