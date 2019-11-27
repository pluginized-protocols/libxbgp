//
// Created by thomas on 18/03/19.
//

#ifndef FRR_UBPF_PUBLIC_BPF_H
#define FRR_UBPF_PUBLIC_BPF_H

#include <stdlib.h>
#include <stdint.h>
#include "tools_ubpf_api.h"


/**
 * Send data pointed to the first argument to the monitoring thread.
 * @param data pointer related to the data the uBPF wants to send to the monitor thread
 * @param len total length of the data
 * @param type which kind of monitoring data the uBPF plugin sends
 * @return 1 if the operation succeed
 *         0 otherwise ( - unable to reach the monitor
 *                       - out of memory when creating packet
 *                       - send failed )
 */
extern int send_to_monitor(const void *data, size_t len, unsigned int type);

extern int get_time(uint64_t *time);

extern clock_t bpf_clock();

extern void *ebpf_memcpy(void *dst0, const void *src0, size_t length);

extern void ebpf_print(const char *format, ...);

extern void set_error(const char *reason, size_t len);

extern void *ctx_malloc(size_t size);

extern void *ctx_calloc(size_t nmemb, size_t size);

extern void *ctx_realloc(void *ptr, size_t size);

extern void ctx_free(void *ptr);

extern void *ctx_shmnew(key_t key, size_t size);

extern void *ctx_shmget(key_t key);

extern void ctx_shmrm(key_t key);

extern uint32_t ebpf_ntohs(uint16_t value);

extern uint32_t ebpf_ntohl(uint32_t value);

extern uint32_t ebpf_ntohll(uint64_t value);

extern int send_ipc_msg(ebpf_message_t *msg);

extern void *bpf_get_args(unsigned int arg_nb, bpf_full_args_t *args);

extern int bpf_sockunion_cmp(const union sockunion *su1, const union sockunion *su2);


#endif //FRR_UBPF_PUBLIC_BPF_H
