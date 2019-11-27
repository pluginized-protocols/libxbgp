//
// Created by thomas on 5/11/18.
//

#ifndef FRR_THESIS_PLUGINS_MANAGER_H
#define FRR_THESIS_PLUGINS_MANAGER_H


//#include "lib/prefix.h"

#include <include/plugin_arguments.h>
#include "include/public.h"
#include <bpf_plugin.h>
#include "map.h"


#define MAX_PLUGINS 128

#define MAX_REASON 2048

#define E_BPF_SHMEM_KEY 220
#define E_BPF_QUEUE_KEY 221  // TOTALLY RANDOM IDENTIFIER 8-bits only
#define E_BPF_QUEUE_PATH DAEMON_VTY_DIR

#define E_BPF_ADD 1
#define E_BPF_RM 2
#define E_BPF_REPLACE 3

#define MAX_SIZE_PLUGIN 1048576
#define MAX_SIZE_NAME_SUB_PLUGIN  50
#define DEFAULT_SHARED_HEAP_SIZE 65536

#define PLUGIN_ALREADY_LOADED_ERROR \
    "A plugin is already loaded for this location\n" \
    "Please remove it before loading a new one"

#define PLUGIN_RM_ERROR_ID_NEG "id plugin must be strictly greater than 0"
#define PLUGIN_RM_ERROR_404 "No plugin attached to this ID (location)"

#define PLUGIN_OK "SUCCESS"

#define MTYPE_EBPF_ACTION 1
#define MTYPE_INFO_MSG 2

// BGP_NOT_ASSIGNED_TO_ANY_FUNCTION is useful to
// add new steps not related to existing functions in
// the protocol code. For example it is used in the
// BGP decision process to add new steps.
// Every non assigned plugins to a entry point (functions)
// MUST use an higher ID than the number attributed for
// BGP_NOT_ASSIGNED_TO_ANY_FUNCTION
// Adding a plugin with ID > BGP_NOT_ASSIGNED_TO_ANY_FUNCTION
// MUST use a different function to be correctly run
// --> SEE plugins_manager.c
// Indeed, this kind of plugin must be handled in a different
// way than a one executed inside a real function (need to
// manually call run_pre, run_replace and run_post)
/*
static const struct {
    plugin_type_t val;
    const char *str;
} conversion_id_plugin[] = {
        {BGP_TEST,                       "bgp_test"},
        {BGP_KEEPALIVE,                  "bgp_keepalive"},
        {BGP_OPEN_MSG,                   "bgp_open_msg"},
        {BGP_UPDATE_TIME_MSG,            "bgp_update_time_msg"},
        {BGP_PREFIX_UPDATE,              "bgp_prefix_update"},
        {BGP_PREFIX_UPDATE_TEST,         "bgp_prefix_update_test"},
        {BGP_PREFIX_WITHDRAW,            "bgp_prefix_withdraw"},
        {BGP_ASPATH_SEND,                "bgp_aspath_send"},
        {BGP_DECISION_PROCESS,           "bgp_decision_process"},
        {BGP_INVALID_UPDATE_INBOUND,     "bgp_invalid_update_inbound"},
        {BGP_DECISION_WEIGHT,            "bgp_decision_weight"},
        {BGP_DECISION_LOCAL_PREF,        "bgp_decision_local_pref"},
        {BGP_DECISION_LOCAL_ROUTE,       "bgp_decision_local_route"},
        {BGP_DECISION_ASPATH,            "bgp_decision_aspath"},
        {BGP_DECISION_ORIGIN_CHECK,      "bgp_decision_origin_check"},
        {BGP_DECISION_MED_CHECK,         "bgp_decision_med_check"},
        {BGP_DECISION_PEER_TYPE,         "bgp_decision_peer_type"},
        {BGP_DECISION_CONFED_CHECK,      "bgp_decision_confed_check"},
        {BGP_DECISION_IGP_ALL,           "bgp_decision_igp_all"},
        {BGP_DECISION_PREFER_FIRST_PATH, "bgp_decision_prefer_first_path"},
        {BGP_DECISION_ROUTE_ID,          "bgp_decision_route_id"},
        {BGP_DECISION_CLUSTER_ID_CMP,    "bgp_decision_cluster_id_cmp"},
        {BGP_DECISION_NEIGHBOR_ADDR_CMP, "bgp_decision_neighbor_addr_cmp"},
        {BGP_INPUT_FILTER_APPLY_PROC,    "bgp_input_filter_apply_proc"},
        {BGP_OUTPUT_FILTER_APPLY_PROC,   "bgp_output_filter_apply_proc"},
        {ZEBRA_UBPF_ANNOUNCE_PREFIX,     "bgp_zebra_announce_prefix"},
        {ZEBRA_UBPF_RM_PREFIX,           "bgp_zebra_rm_prefix"},
        {OSPF_SPF_NEXT,                  "ospf_spf_next"},
        {OSPF_SPF_CALCULATE,             "ospf_spf_calculate"},
        {OSPF_LSA_FLOOD,                 "ospf_lsa_flood"},
        {OSPF_ISM_CHANGE,                "ospf_ism_change"},
        {OSPF_HELLO_SEND,                "ospf_hello_send"}
};*/
/*
static const struct {
    plugin_type_t plug_id;
    argument_type_t args_id;
} map_args_plug_id[] = {
        {BGP_TEST,                       ARGS_INVALID},
        {BGP_KEEPALIVE,                  ARGS_BGP_KEEPALIVE},
        {BGP_OPEN_MSG,                   ARGS_BGP_OPEN},
        {BGP_UPDATE_TIME_MSG,            ARGS_BGP_UPDATE_TIME},
        {BGP_PREFIX_UPDATE,              ARGS_BGP_UPDATE},
        {BGP_PREFIX_UPDATE_TEST,         ARGS_INVALID},
        {BGP_PREFIX_WITHDRAW,            ARGS_BGP_INVALID_UPDATE},
        {BGP_ASPATH_SEND,                ARGS_BGP_ASPATH_RECV},
        {BGP_DECISION_PROCESS,           ARGS_BGP_DECISION_PROCESS},
        {BGP_INVALID_UPDATE_INBOUND,     ARGS_BGP_WITHDRAW_IN_FILTER},
        {BGP_DECISION_WEIGHT,            ARGS_DECISION_STEPS},
        {BGP_DECISION_LOCAL_PREF,        ARGS_DECISION_STEPS},
        {BGP_DECISION_LOCAL_ROUTE,       ARGS_DECISION_STEPS},
        {BGP_DECISION_ASPATH,            ARGS_DECISION_STEPS},
        {BGP_DECISION_ORIGIN_CHECK,      ARGS_DECISION_STEPS},
        {BGP_DECISION_MED_CHECK,         ARGS_DECISION_STEPS},
        {BGP_DECISION_PEER_TYPE,         ARGS_DECISION_STEPS},
        {BGP_DECISION_CONFED_CHECK,      ARGS_DECISION_STEPS},
        {BGP_DECISION_IGP_ALL,           ARGS_DECISION_STEPS},
        {BGP_DECISION_PREFER_FIRST_PATH, ARGS_DECISION_STEPS},
        {BGP_DECISION_ROUTE_ID,          ARGS_DECISION_STEPS},
        {BGP_DECISION_CLUSTER_ID_CMP,    ARGS_DECISION_STEPS},
        {BGP_DECISION_NEIGHBOR_ADDR_CMP, ARGS_DECISION_STEPS},
        {BGP_INPUT_FILTER_APPLY_PROC,    ARGS_BGP_PROC_INPUT_FILTER},
        {BGP_OUTPUT_FILTER_APPLY_PROC,   ARGS_BGP_PROC_OUTPUT_FILTER},
        {ZEBRA_UBPF_ANNOUNCE_PREFIX,     ARGS_ZEBRA_ANNOUNCE_PREFIX},
        {ZEBRA_UBPF_RM_PREFIX,           ARGS_ZEBRA_RM_PREFIX},
        {OSPF_SPF_NEXT,                  ARGS_OSPF_SPF_NEXT},
        {OSPF_SPF_CALCULATE,             ARGS_OSPF_SPF_CALCULATE},
        {OSPF_LSA_FLOOD,                 ARGS_OSPF_LSA_FLOOD},
        {OSPF_ISM_CHANGE,                ARGS_OSPF_ISM_CHANGE},
        {OSPF_HELLO_SEND,                ARGS_OSPF_HELLO_SEND}
};*/

typedef struct ubpf_queue_msg {

    long mtype;
    unsigned int plugin_action;
    unsigned int location;
    unsigned int plugin_type;
    uint8_t jit;
    char name[MAX_SIZE_NAME_SUB_PLUGIN];
    char after[MAX_SIZE_NAME_SUB_PLUGIN];
    size_t length; // if add or replace
} ubpf_queue_msg_t;

typedef struct ubpf_queue_info_msg {

    long mtype;
    int status; // failed or not
    char reason[MAX_REASON];

} ubpf_queue_info_msg_t;

typedef map_t(plugin_t *) vm_container_map_t;


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
int add_plugin(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_plugin,
               const char *sub_plugin_name, uint8_t jit, const char *after);

/**
 * Run the plugin associated to the ID given at argument. This ID should be
 * associated to an already registered plugin. Otherwise the function will fails
 * by returning 0.
 * @param plugin_manager pointer to the associated plugin_manager (already initialized). Should NOT be NULL
 * @param plug_id which plugin to run. The ID must correspond to an already registered plugin
 * @param mem pointer to the argument to pass to the uBPF plugin (should not be NULL)
 * @param mem_len total length of this argument
 * @param ret_val pointer pointing to the memory where the uBPF plugin must store its return value.
 * @return 1 if operation succeeded.
 *         0 otherwise ( - invalid ID
 *                       - uBPF plugin crashed )
 */
//int run_plugin(plugins_t *plugin_manager, int plug_id, void *mem, size_t mem_len, uint64_t *ret_val);
// not used anymore

int plugin_is_registered(int plugin_id);

int run_plugin_pre(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int run_plugin_post(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int init_ubpf_inject_queue(int type);

int init_upbf_inject_queue_snd(void);

int init_ubpf_inject_queue_rcv(void);

int send_plugin(const char *path, size_t path_len, unsigned int location, unsigned int action, int msqid);

int rm_plugin(int id_plugin, const char **err);

int __add_plugin_ptr(const uint8_t *bytecode, int id_plugin, int type_plugin, size_t len,
                     size_t add_mem_len, size_t shared_mem, const char *sub_plugin_name, const char *after, uint8_t jit, const char **err);

int __add_plugin(const char *path_code, int id_plugin, int type_plugin, size_t add_mem_len, size_t shared_mem,
                 const char *sub_plugin_name, const char *after, uint8_t jit, const char **err);

int run_volatile_plugin(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int is_volatile_plugin(int plugin_id);

// (plugins_t *plugin_manager, void *generic_ptr, int id_plugin, int type_plug, int type_ptr, size_t len, size_t add_mem_len,
//                     const char **err)

// plugin_type_t id_plugin_to_enum(const char *str);

// argument_type_t get_args_id_by_plug_id(plugin_type_t type);

int load_from_json(const char *file_path, const char *sysconfdir);

int load_monit_info(const char *file_path, char *addr, size_t len_addr, char *port, size_t len_port);

size_t store_plugin(size_t size, const char *path);

int notify_deactivate_replace(plugins_t *plugins1, int plug_id);

void remove_xsi(void);

#endif //FRR_THESIS_PLUGINS_MANAGER_H
