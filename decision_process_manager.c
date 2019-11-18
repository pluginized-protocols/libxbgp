//
// Created by thomas on 20/02/19.
//

#include <plugins_manager.h>
#include "include/decision_process_manager.h"
#include <ubpf_prereq.h>
#include <include/ebpf_mod_struct.h>
#include <bgpd/bgp_ubpf_api.h>
#include "bpf_plugin.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgpd.h"

#include "bgpd/bgp_decision_steps.h"

static int run_normal_operation(decision_context_t *dctx, bpf_full_args_t *args) {

    int i;

    for (i = BGP_DECISION_WEIGHT; i != BGP_SPEC_COMP_1 && i != BGP_SPEC_COMP_2;) {

        i = dctx->operations[i](args);

    }
    return i;
}


static inline void turn_off_plugins_decision_process() {
    notify_deactivate_replace(plugins_manager, BGP_DECISION_WEIGHT);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_LOCAL_PREF);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_LOCAL_ROUTE);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_ASPATH);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_ORIGIN_CHECK);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_MED_CHECK);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_PEER_TYPE);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_CONFED_CHECK);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_IGP_ALL);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_PREFER_FIRST_PATH);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_ROUTE_ID);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_CLUSTER_ID_CMP);
    notify_deactivate_replace(plugins_manager, BGP_DECISION_NEIGHBOR_ADDR_CMP);
}

static int is_state_valid(unsigned int state) {

    if(state <= 0) return 0;
    if(state >= BGP_NOT_ASSIGNED_TO_ANY_FUNCTION) return 0;

    return 1;
}

int run_decision_steps(decision_context_t *dctx, struct bgp_path_info *new,
                       struct bgp_path_info *exist, struct bgp *bgp,
                       struct bgp_maxpaths_cfg *mpath_cfg, int *paths_eq) {

    // BGP_SPEC_COMP_1 --> OLD/EXISTS
    // BGP_SPEC_COMP_2 --> NEW

    int curr_state, previous_state;
    uint64_t ret_val = BGP_SPEC_COMP_1;

    if (!new || !exist || !dctx) return -1;

    bgp_ebpf_t light_bgp;
    copy_bgp_to_ebpf(bgp, &light_bgp);

    bpf_args_t args_gen[6] = {
            [0] = {.arg = dctx, .len = sizeof(decision_context_t), .kind = kind_ptr, .type = BPF_ARG_DEC_STEPS},
            [1] = {.arg = exist, .len = sizeof(struct bgp_path_info), .kind = kind_ptr, .type = BPF_ARG_PATH_INFO},
            [2] = {.arg = new, .len = sizeof(struct bgp_path_info), .kind = kind_ptr, .type = BPF_ARG_PATH_INFO},
            [3] = {.arg = &light_bgp, .len = sizeof(bgp_ebpf_t), .kind = kind_ptr, .type = BPF_ARG_BGP},
            [4] = {.arg = mpath_cfg, .len = sizeof(struct bgp_maxpaths_cfg), .kind = kind_ptr, .type = BPF_ARG_MAXPATH_CFG},
            [5] = {.arg = &paths_eq, .len = sizeof(int), .kind = kind_ptr, .type = BPF_ARG_INT_MOD},
    };

    bpf_full_args_t fargs;

    previous_state = -1;

    for (curr_state = dctx->init_step; curr_state != BGP_SPEC_COMP_1 && curr_state != BGP_SPEC_COMP_2 && curr_state != BGP_SPEC_ERROR;) {
        new_argument(args_gen, 0, 6, &fargs); // TODO because yellow
        if (plugin_is_registered(curr_state)) {
            if(is_volatile_plugin(curr_state)) {
                if(!run_volatile_plugin(curr_state, &fargs, sizeof(bpf_full_args_t *), &ret_val)){
                    goto err;
                }
            } else {
                ret_val = dctx->operations[curr_state](&fargs);
            }
            previous_state = curr_state;
            curr_state = (int) ret_val;

            if (ret_val == BGP_SPEC_ERROR || ret_val == UINT64_MAX) {
                goto err;
            }
        } else {
            if(!is_state_valid(curr_state)) {
                fprintf(stderr, "Unknown static state (%u)\n", curr_state);
                goto err;
            } else {
                curr_state = dctx->operations[curr_state](&fargs);
            }
        }
    }

    // fprintf(stderr, "\033[1;32mSUCCEEDED !\033[0m BGP pluginized decision process was a total SUCCESS\n");
    return (int) ret_val;

    err:
    turn_off_plugins_decision_process();
    fprintf(stderr, "\033[1;31mFATAL ! Reset BGP decision process and replay it with original code "
                    "without executing REPLACE part of the plugin (%s)\033[0m\n",
                    id_plugin_to_str(previous_state));

    unset_args(&fargs);
    return run_normal_operation(dctx, &fargs);

}
