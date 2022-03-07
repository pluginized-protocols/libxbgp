//
// Created by thomas on 5/11/18.
//

#ifndef FRR_THESIS_PLUGINS_MANAGER_H
#define FRR_THESIS_PLUGINS_MANAGER_H


//#include "lib/ubpf_prefix.h"



#include <include/ebpf_mod_struct.h>
#include <pthread.h>
#include <limits.h>
#include <stdint.h>
#include <include/context_hdr.h>
#include "insertion_point.h"
#include "log.h"
#include "shared_memory.h"

#define MAX_SIZE_PLUGIN 1048576
#define MAX_SIZE_OBJ_CODE 1048576
#define MTYPE_EBPF_ACTION 1
#define MTYPE_INFO_MSG 2


enum msg_type_id {
    E_BPF_ADD = 1,
    E_BPF_RM,
    E_BPF_RM_PLUGLET,
    E_BPF_REPLACE,
    E_BPF_CHANGE_MONITORING,
    E_BPF_TRANSACTION,
    E_BPF_TRANSACTION_BEGIN,
    E_BPF_TRANSACTION_ADD,
    E_BPF_TRANSACTION_END,
};

typedef enum status_message_passing {

    STATUS_MSG_OK,
    STATUS_MSG_TRANSACTION_FAIL,
    STATUS_MSG_TRANSACTION_NOT_BEGIN,
    STATUS_MSG_TRANSACTION_IN_PROGRESS,
    STATUS_MSG_NO_TRANSACTION,
    STATUS_MSG_PLUGLET_INSERT_FAIL,
    STATUS_MSG_PLUGLET_RM_FAIL,
    STATUS_MSG_PLUGLET_ANCHOR_NOT_RECOGNISED,
    STATUS_MSG_PLUGIN_RM_FAIL,

    STATUS_MSG_INTERNAL_ERROR,
    STATUS_MSG_PLUGIN_ID_IS_NEGATIVE,
    STATUS_MSG_MEMALLOC_ERR,

    STATUS_MSG_RM_ERROR_ID_NEGATIVE,
    STATUS_MSG_RM_ERROR_NOT_FOUND,

} status_t;

typedef struct vm_container vm_container_t;
typedef struct insertion_point insertion_point_t;
typedef struct insertion_point_iterator insertrion_point_iterator_t;
typedef struct plugin plugin_t;


typedef struct manager {

    insertion_point_info_t *point_info;
    struct proto_ext_fun *helper_functions;
    vm_container_t *vms_table;
    plugin_t *plugin_table;
    insertion_point_t *insertion_point_table;

    char var_state_path[PATH_MAX]; /* path to the folder where this manager will store temporary files */


} manager_t;

/**
 * Initialise the plugin manager by allocating required memory.
 * This function will init the above plugin_manager (global variable).
 * Ideally this function must be called at program start
 * @return 1 if the operation succeed
 *         0 otherwise
 */
int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *process_vty_dir,
                    insertion_point_info_t *plugins_array,
                    int dbg, struct log_config *logs);

/**
 *
 * @param plugin_name
 * @param plugin_name_len
 * @param extra_mem
 * @param shared_mem
 * @param insertion_point_id
 * @param insertion_point
 * @param i_pt_name
 * @param type_anchor
 * @param seq_anchor
 * @param jit
 * @param obj_path_code
 * @param vm_name
 * @param vm_name_len
 * @param api_proto
 * @return
 */
int add_extension_code(const char *plugin_name, size_t plugin_name_len, uint64_t extra_mem, uint64_t shared_mem,
                       int insertion_point_id, const char *insertion_point, size_t i_pt_name, anchor_t type_anchor,
                       int seq_anchor, int jit,
                       const char *obj_path_code, size_t len_obj_path_code,
                       const char *vm_name, size_t vm_name_len, proto_ext_fun_t *api_proto, int permission,
                       int add_memcheck_insts, mem_type_t memory_mgt, int use_libffi);


void ubpf_terminate(void);

int close_shared_memory(void);

int str_insertion_point_to_int(manager_t *manager, const char *plugin_str);

insertion_point_t *insertion_point(int id);

plugin_t *plugin_by_name(const char *name);

vm_container_t *vm_by_name(const char *name);

const char *id_insertion_point_to_str(manager_t *manager, int id);

insertion_point_t *get_insertion_point(manager_t *manager, int id);

int is_plugin_registered(manager_t *manager, plugin_t *p);

int register_plugin(manager_t *manager, plugin_t *plugin);

int unregister_plugin(manager_t *manager, const char *name);

int insertion_point_is_registered(manager_t *manager, insertion_point_t *point);

int register_insertion_point(manager_t *manager, insertion_point_t *point);

int context_is_registered(manager_t *manager, context_t *ctx);

int register_context(manager_t *manager, context_t *ctx);

int register_vm(manager_t *manager, vm_container_t *vm);

int is_vm_registered(manager_t *manager, vm_container_t *vm);

int is_vm_registered_by_name(manager_t *manager, const char *name);

plugin_t *get_plugin_by_name(manager_t *manager, const char *name);

int is_plugin_registered_by_name(manager_t *manager, const char *name);

int insertion_point_is_registered_by_id(manager_t *manager, int id);

int unregister_insertion_point(manager_t *manager, int id);

void *readfile(const char *path, size_t maxlen, size_t *len);

vm_container_t *unregister_vm(manager_t *manager, const char *name);

insertion_point_t *get_insertion_point_by_id(manager_t *manager, int id);

int remove_extension_code(const char *name);

int remove_plugin(const char *name);

int remove_insertion_point(int id);

insertion_point_info_t *get_insertion_point_info(void);

#endif //FRR_THESIS_PLUGINS_MANAGER_H
