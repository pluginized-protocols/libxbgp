//
// Created by thomas on 28/05/19.
//

#include "ubpf_tools/include/public_bpf.h"
#include <lib/prefix.h>


struct announce_msg {

    clock_t clock;
    uint32_t type;

};

uint64_t pre_on_withdraw(bpf_full_args_t *args) {

    ebpf_message_t msg;
    struct prefix *p = bpf_get_args(0, args);
    if (!p) return EXIT_FAILURE;

    struct announce_msg content = {.clock = clock(), .type = p->u.prefix4.s_addr};
    ctx_free(p);

    msg.mesg_type = TYPE_MSG_MONITOR;
    memcpy(&msg.mesg_text, &content, sizeof(struct announce_msg));

    send_ipc_msg(&msg);

    return EXIT_SUCCESS;
}