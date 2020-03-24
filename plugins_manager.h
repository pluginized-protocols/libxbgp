//
// Created by thomas on 5/11/18.
//

#ifndef FRR_THESIS_PLUGINS_MANAGER_H
#define FRR_THESIS_PLUGINS_MANAGER_H


//#include "lib/ubpf_prefix.h"

#include <include/plugin_arguments.h>
#include <bpf_plugin.h>
#include "map.h"
#include <limits.h>


#define MAX_PLUGINS 128
#define MAX_SIZE_PLUGIN 1048576
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


typedef struct ubpf_queue_msg {

    long mtype;
    unsigned int plugin_action;
    short jit;
    char plugin_name[NAME_MAX + 1];
    size_t bytecode_length;
    int hook;
    uint32_t seq;
    uint16_t extra_memory;
    uint16_t shared_memory;

} ubpf_queue_msg_t;

typedef struct ubpf_queue_info_msg {

    long mtype;
    status_t status; // failed or not

} ubpf_queue_info_msg_t;

typedef map_t(plugin_t *) vm_container_map_t;

typedef int (*new_plug)(const char *name_plugin, const char *path_plugin,
                        size_t extra_memory, size_t shared_memory,
                        int plugin_id, int pluglet_type,
                        uint32_t sequence, uint8_t jit);


typedef struct plugins {

    int size; // number of plugins already registered

    plugin_t *ubpf_machines[MAX_PLUGINS];

    //vm_container_map_t *ubpf_machines;
    // map containing current uBPF plugins.
    // keys are actually ID associated to a particular
    // uBPF machine which contains a particular plugin

} plugins_t;

/**
 * Global plugin manager which could be accessed
 * everywhere in the BGP code.
 */
extern plugins_t *plugins_manager;

/**
 * Initialise the plugin manager by allocating required memory.
 * This function will init the above plugin_manager (global variable).
 * Ideally this function must be called at program start
 * @return 1 if the operation succeed
 *         0 otherwise
 */
int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *process_vty_dir, size_t len, plugin_info_t *plugins_array,
                    const char *monitoring_address, const char *monitoring_port, int require_monit);

/**
 * Add an uBPF plugin to the plugin_manager given in argument
 * @param plugin_manager pointer to the associated plugin_manager. Pointer should not be NULL
 * @param path_code path to the compiled uBPF plugin (with clang)
 * @param id_plugin which id must this plugin use (required later to run a particular plugin)
 * @return 1 if the operation succeed
 *         0 otherwise ( - ID is already used by another plugin,
 *                       - invalid path
 *                       - provided uBPF file contains errors
 *                       - unable to allocate new memory for this plugin )
 */
int add_pluglet(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_plugglet,
                uint32_t seq, uint8_t jit);

int plugin_is_registered(int plugin_id);

int run_plugin_pre(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int run_plugin_post(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int init_ubpf_inject_queue(void);

int send_pluglet(const char *path, const char *plugin_name, short jit, int hook, unsigned int action,
                 uint16_t extra_mem, uint16_t shared_mem, uint32_t seq, int msqid, int shared_fd);

int rm_plugin(int id_plugin, int *err);

int rm_plugin_str(const char *str, const char **err);

int __add_pluglet_ptr(const uint8_t *bytecode, int id_plugin, int type_plugin, size_t len,
                      size_t add_mem_len, size_t shared_mem, uint32_t seq, uint8_t jit,
                      int *err);

int __add_pluglet(const char *path_code, int id_plugin, int type_plugin, size_t add_mem_len, size_t shared_mem,
                  uint32_t seq, uint8_t jit, int *err);

int run_volatile_plugin(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int is_volatile_plugin(int plugin_id);

int load_plugin_from_json(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir);

int load_plugin_from_json_fn(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir, new_plug fn);

size_t store_plugin(size_t size, const char *path, int shared_fd);

void remove_xsi(void);

void ubpf_terminate(void);

int rm_pluglet(int plugin_id, int seq, int anchor);

int send_rm_plugin(int msqid, const char *plugin_name);

int send_rm_pluglet(int msqid, const char *plugin_name, uint32_t seq, int anchor);

int send_begin_transaction(int msqid);

int send_finish_transaction(int msqid);

int init_shared_memory(char *shared_mem_name);

plugin_info_t *get_plugin_info(void);

int get_max_plugins(void);

int get_msqid(void);

int close_shared_memory(void);

#endif //FRR_THESIS_PLUGINS_MANAGER_H
