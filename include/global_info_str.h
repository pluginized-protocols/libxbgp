//
// Created by thomas on 1/06/20.
//

#ifndef UBPF_TOOLS_GLOBAL_INFO_STR_H
#define UBPF_TOOLS_GLOBAL_INFO_STR_H

#define L_DEBUG "\001"            /* Debugging messages */
#define L_TRACE "\002"            /* Protocol tracing */
#define L_INFO "\003"            /* Informational messages */
#define L_REMOTE "\004"            /* Remote protocol errors */
#define L_WARN "\005"            /* Local warnings */
#define L_ERR "\006"            /* Local errors */
#define L_AUTH "\007"            /* Authorization failed etc. */
#define L_FATAL "\010"            /* Fatal errors */
#define L_BUG "\011"            /* BIRD bugs */


struct global_info {
    void *hidden_ptr;
    int type;
};

#endif //UBPF_TOOLS_GLOBAL_INFO_STR_H
