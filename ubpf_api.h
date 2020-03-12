//
// Created by thomas on 4/11/18.
//

#ifndef FRR_THESIS_UBPF_API_H
#define FRR_THESIS_UBPF_API_H

#include "ubpf_manager.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define OFFSET_UNIX_EPOCH_TO_NTP 2208988800
#define SOCKET_PATH "\0monitor_ubpf_plug.socket"

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
int send_to_monitor(context_t *vm_ctx, const void *data, size_t len, unsigned int type);

/**
 * Allocate a new shared memory accessible by every uBPF plugin
 * @param id to the shared zone
 * @param shared_zone pointer to uBPF zone to copy in the shared zone
 * @param len total length of the memory to allocate
 * @return 1 if the allocation succeed
 *         0 otherwise ( - out of memory
 *                       - id already took by other plugin )
 */
//void *new_shared_memory(int id, void *shared_zone, size_t len);

/**
 * Get the memory related to the id given at argument
 * @param id shared memory identifier
 * @param access_pointer pointer to the uBPF zone where the shared zone will be copied
 * @return 0 if memory not found
 *         else 1
 */
//int get_shared_memory(int id, void *access_pointer);

/**
 * Delete the shared memory associated to the id given at argument.
 * @param id shared memory identifier
 * @return 1 if ok
 *         0 if memory not found
 */
// int destroy_shared_memory(int id);

int get_time(context_t *vm_ctx, uint64_t *time);

clock_t bpf_clock(context_t *vm_ctx);

char *as_path_store_from_attr(context_t *vm_ctx, bpf_full_args_t *args, int nb_arg, size_t *total_len);

void *ebpf_memcpy(context_t *vm_ctx, void *dst0, const void *src0, size_t length);

void ebpf_print(context_t *vm_ctx, const char *format, ...);

void set_error(context_t *vm_ctx, const char *reason, size_t len);

void *ctx_malloc(context_t *vm_ctx, size_t size);

void *ctx_calloc(context_t *vm_ctx, size_t nmemb, size_t size);

void *ctx_realloc(context_t *vm_ctx, void *ptr, size_t size);

void ctx_free(context_t *vm_ctx, void *ptr);

void *ctx_shmnew(context_t *vm_ctx, key_t key, size_t size);

void *ctx_shmget(context_t *vm_ctx, key_t key);

void ctx_shmrm(context_t *vm_ctx, key_t key);

void membound_fail(context_t *ctx, uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr);

void rm_ipc(void);

int send_ipc_msg(context_t *vm_ctx, ebpf_message_t *msg);

int init_queue_ext_send(const char *working_dir);

void *bpf_get_args(context_t *vm_ctx, unsigned int arg_nb, bpf_full_args_t *args);

int bpf_sockunion_cmp(context_t *vm_ctx, const struct sockaddr *su1, const struct sockaddr *su2);

uint64_t ebpf_sqrt(context_t *ctx, uint64_t a, unsigned int precision);

#endif //FRR_THESIS_UBPF_API_H
