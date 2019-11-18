//
// Created by thomas on 20/02/19.
//

#ifndef FRR_UBPF_DECISION_PROCESS_MANAGER_H
#define FRR_UBPF_DECISION_PROCESS_MANAGER_H

#include "ubpf_tools/include/plugins_id.h"

typedef struct dec_args dec_args_t;

typedef uint64_t (*decision_step)(bpf_full_args_t *);

/*typedef enum REPLACE_RETURN_VALUE {
    DECISION_ERROR,  // used to handing back to the
    DECISION_FINISH,
    DECISION_INIT,
    DECISION_OLD,
    DECISION_NEW,

    DECISION_WEIGHT, // note, true order respected in this enum
    DECISION_LOCAL_PREF,
    DECISION_LOCAL_ROUTE,
    DECISION_AS_PATH,
    DECISION_ORIGIN,
    DECISION_MED,
    DECISION_PEER_TYPE,
    DECISION_IGP,
    DECISION_SAME_IGP,
    DECISION_CONFED,
    DECISION_MAX_PATH,
    DECISION_EXTERNAL_FIRST,
    DECISION_ROUTER_ID,
    DECISION_CLUSTER_LENGTH,
    DECISION_NEIGHBOR_ADDR,
    DECISION_MAX,

} decision_type_t;*/

typedef struct decision_context {

    decision_step operations[BGP_NOT_ASSIGNED_TO_ANY_FUNCTION];
    int init_step;
    int next_step; // or done !


} decision_context_t;

struct dec_args {
    uintptr_t ctx;  // this is the context of the virtual machine
    decision_context_t *decision; // must be common for all uBPF VMs

    // this is plugins' real arguments
    struct bgp_path_info *new; // the new attribute of received prefix
    struct bgp_path_info *exist; // compare with one prefix already received
    struct bgp *bgp;
    struct bgp_maxpaths_cfg *mpath_cfg;
    int *paths_eq;
};

// dctx must have a life time longer than the call to this function.
extern int run_decision_steps(decision_context_t *dctx, struct bgp_path_info *new,
                       struct bgp_path_info *exist, struct bgp *bgp,
                       struct bgp_maxpaths_cfg *mpath_cfg, int *paths_eq);


#endif //FRR_UBPF_DECISION_PROCESS_MANAGER_H
