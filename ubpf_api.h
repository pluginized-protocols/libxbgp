//
// Created by thomas on 4/11/18.
//

#ifndef FRR_THESIS_UBPF_API_H
#define FRR_THESIS_UBPF_API_H

#include "ubpf_manager.h"
#include "plugin_socket.h"
#include <xbgp_compliant_api/xbgp_common_vm_defs.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define OFFSET_UNIX_EPOCH_TO_NTP 2208988800
#define SOCKET_PATH "\0monitor_ubpf_plug.socket"

extern proto_ext_fun_t base_api_fun__[];
extern const int base_api_fun_len__;

int get_time(context_t *vm_ctx, struct timespec *spec);

void *ebpf_memcpy(context_t *vm_ctx, void *dst0, const void *src0, uint64_t length);

int ebpf_print_intern(context_t *vm_ctx, const char *format, struct vargs *args);

void *ctx_malloc(context_t *vm_ctx, uint64_t size);

void *ctx_calloc(context_t *vm_ctx, uint64_t nmemb, uint64_t size);

void *ctx_realloc(context_t *vm_ctx, void *ptr, uint64_t size);

void ctx_free(context_t *vm_ctx, void *ptr);

void *ctx_shmnew(context_t *vm_ctx, key_t key, uint64_t size);

void *ctx_shmget(context_t *vm_ctx, key_t key);

void ctx_shmrm(context_t *vm_ctx, key_t key);

void membound_fail(context_t *ctx, uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr);

void *get_arg(context_t *vm_ctx, int type);

uint64_t ebpf_sqrt(context_t *ctx, uint64_t a, unsigned int precision);

int ebpf_memcmp(context_t *ctx, const void *s1, const void *s2, uint64_t n);

int ebpf_bvsnprintf(context_t *ctx, char *buf, int size, const char *fmt, uintptr_t *args);

int next(context_t *vm_ctx);

int get_extra_info_value(context_t *ctx, struct global_info *info, void *buf, uint64_t len_buf);

int get_extra_info_lst_idx(context_t *ctx, struct global_info *info, int arr_idx, struct global_info *value);

int get_extra_info_dict(context_t *ctx, struct global_info *info, const char *key, struct global_info *value);

int get_extra_info(context_t *ctx, const char *key, struct global_info *info);

int ebpf_inet_ntop(context_t *ctx, uint8_t *ipaddr, int type, char *buf, uint64_t len);

int ebpf_inet_pton(context_t *ctx, int af, const char *src, void *dst, uint64_t buf_len);

uint16_t super_ntohs(context_t *ctx, uint16_t value);

uint32_t super_ntohl(context_t *ctx, uint32_t value);

uint64_t super_ntohll(context_t *ctx, uint64_t value);

uint16_t super_htons(context_t *ctx __attribute__((unused)), uint16_t val);

uint32_t super_htonl(context_t *ctx __attribute__((unused)), uint32_t val);

uint64_t super_htonll(context_t *ctx, uint64_t val);

int fetch_file(context_t *ctx, char *url, const char *dest);

int super_log(context_t *vm_ctx, const char *msg, struct vargs *args);

int sk_open(context_t *ctx, sk_type_t proto, int af, const struct sockaddr *addr, socklen_t len);

int sk_write(context_t *ctx, int sfd, const void *buf, uint64_t len);

int sk_read(context_t *ctx, int sfd, void *buf, uint64_t len);

int sk_close(context_t *ctx, int sfd);

int reschedule_plugin(context_t *ctx, time_t *time);

#endif //FRR_THESIS_UBPF_API_H
