//
// Created by thomas on 18/03/19.
//

#ifndef FRR_UBPF_PUBLIC_BPF_H
#define FRR_UBPF_PUBLIC_BPF_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include "ebpf_mod_struct.h"
#include "global_info_str.h"
#include "plugin_arguments.h"
#include "tools_ubpf_api.h"


#define NUMARGS_SPRINTF__(...)  (sizeof((uintptr_t[]){__VA_ARGS__})/sizeof(uintptr_t))

#define ubpf_sprintf(str, size, format, ...)\
ebpf_bvsnprintf(str, size, format, (uintptr_t[]){NUMARGS_SPRINTF__(__VA_ARGS__), __VA_ARGS__})


/**
 * Send data pointed by the first argument to the monitoring thread.
 * @param data pointer related to the data the uBPF wants to send to the monitor thread
 * @param len total length of the data
 * @param type which kind of monitoring data the uBPF plugin sends
 * @return 1 if the operation succeed
 *         0 otherwise ( - unable to reach the monitor
 *                       - out of memory when creating packet
 *                       - send failed )
 */
extern int send_to_monitor(const void *data, size_t len, unsigned int type);

extern int get_time(struct timespec *spec);

extern clock_t bpf_clock(void);

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

extern uint16_t ebpf_ntohs(uint16_t value);

extern uint32_t ebpf_ntohl(uint32_t value);

extern uint64_t ebpf_ntohll(uint64_t value);

extern uint16_t ebpf_htons(uint16_t value);

extern uint32_t ebpf_htonl(uint32_t value);

extern uint64_t ebpf_htonll(uint64_t value);

extern int send_ipc_msg(ebpf_message_t *msg);

extern void *get_arg(unsigned int arg_type);

extern int bpf_sockunion_cmp(const struct sockaddr *su1, const struct sockaddr *su2);

extern uint64_t ebpf_sqrt(uint64_t a, unsigned int precision);

extern int ebpf_memcmp(const void *s1, const void *s2, size_t n);

extern int ebpf_bvsnprintf(char *buf, int size, const char *fmt, uintptr_t *args);

extern int next(void);

extern int get_extra_info_value(struct global_info *info, void *buf, size_t len_buf);

extern int get_extra_info_lst_idx(struct global_info *info, int arr_idx, struct global_info *value);

extern int get_extra_info(const char *key, struct global_info *info);

extern int get_extra_info_dict(struct global_info *info, const char *key, struct global_info *value);

extern int ebpf_inet_ntop(uint8_t *ipaddr, int type, char *buf, size_t len);

extern int super_log(const char *msg, struct vargs *args);

#endif //FRR_UBPF_PUBLIC_BPF_H
