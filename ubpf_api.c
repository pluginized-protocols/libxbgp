//
// Created by thomas on 4/11/18.
//

#include <sys/un.h>
#include "include/monitoring_struct.h"
#include <include/plugin_arguments.h>
#include "include/ebpf_mod_struct.h"
#include <json-c/json_object.h>
#include <ubpf_api.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "ubpf_context.h"

#include "include/tools_ubpf_api.h"
#include "bpf_plugin.h"
#include <unistd.h>

#include "stdarg.h"

#include <netinet/in.h>


static int write_fd = -1; // fd to talk to monitoring manager of this library
static int ebpf_msgid = -1;


int init_queue_ext_send(const char *working_dir) {
    key_t key;
    int msgid;

    // ftok to generate unique key
    key = ftok(working_dir, 65);
    if (key == -1) {
        perror("ftok ebpf msg export error");
        return -1;
    }

    // msgget creates a message queue
    // and returns identifier
    msgid = msgget(key, 0666u | (unsigned int)IPC_CREAT);

    if (msgid < 0) {
        perror("msget error create");
        return -1;
    }

    ebpf_msgid = msgid;
    return msgid;
}

void rm_ipc() {

    if (ebpf_msgid != -1) msgctl(ebpf_msgid, IPC_RMID, NULL);

}

int send_ipc_msg(context_t *ctx, ebpf_message_t *msg) {

    UNUSED(ctx);

    if (ebpf_msgid == -1) {
        fprintf(stderr, "MSGID ERROR not init at main\n");
        return -1;
    }

    if (msgsnd(ebpf_msgid, msg, sizeof(ebpf_message_t), 0) == -1) {
        perror("msgsnd fail (ebpf)");
        return -1;
    }

    return 0;

}

void set_write_fd(int fd) {
    write_fd = fd;
}

static int send_all(int socket, const void *buffer, size_t length) {
    ssize_t n;
    const char *p = buffer;
    while (length > 0) {
        n = write(socket, p, length);
        if (n <= 0) {
            perror("Send failed");
            return -1;
        }
        p += n;
        length -= n;
    }
    return 0;
}

static int packet_send(const void *data, size_t len, unsigned int type, int sock_fd) {

    uint32_t _type = (uint32_t) type;

    if (send_all(sock_fd, &len, sizeof(size_t)) < 0)
        return 0;
    if (send_all(sock_fd, &_type, sizeof(uint32_t)) < 0)
        return 0;
    if (send_all(sock_fd, data, len) < 0)
        return 0;

    return 1;
}

int send_to_monitor(context_t *vm_ctx, const void *data, size_t len, unsigned int type) {

    UNUSED(vm_ctx);

    if(type == 0) return 0;

    if (write_fd == -1) return 0;
    if (!packet_send(data, len, type, write_fd))
        return 0;

    return 1;
}

void *ctx_malloc(context_t *vm_ctx, size_t size) {
    return bump_alloc(&vm_ctx->p->mem.heap.mp, size);
}

void *ctx_calloc(context_t *vm_ctx, size_t nmemb, size_t size) {
    return bump_calloc(&vm_ctx->p->mem.heap.mp, nmemb, size);
}

void *ctx_realloc(context_t *vm_ctx, void *ptr, size_t size) {
    UNUSED(vm_ctx); UNUSED(ptr); UNUSED(size);
    return NULL; // we don't do that here
}

void ctx_free(context_t *vm_ctx, void *ptr) {
    UNUSED(vm_ctx);
    UNUSED(ptr);
    // bump alloc is a stack like alloc --> everything is removed after
    // the plugin call
    // my_free(&vm_ctx->p->heap.mp, ptr);
}

void *ctx_shmnew(context_t *vm_ctx, key_t key, size_t size) {
    void *addr;
    addr = ubpf_shmnew(&vm_ctx->p->mem.shared_heap.smp, key, size);
    memset(addr, 0, size);
    return addr;
}

void *ctx_shmget(context_t *vm_ctx, key_t key) {
    return ubpf_shmget(&vm_ctx->p->mem.shared_heap.smp, key);
}

void ctx_shmrm(context_t *vm_ctx, key_t key) {
    ubpf_shmrm(&vm_ctx->p->mem.shared_heap.smp, key);
}



int get_time(context_t *vm_ctx, uint64_t *time) {
    UNUSED(vm_ctx);
    struct timespec spec;
    uint64_t curr_ntp;
    /* assuming CLOCK_REALTIME returns UTC (UNIX EPOCH
     * is considered as 00:00:00 UTC on 1 January 1970) */
    if (clock_gettime(CLOCK_REALTIME, &spec) != 0) {
        perror("Clock gettime");
        return -1;
    }

    curr_ntp = (uint64_t) spec.tv_sec + OFFSET_UNIX_EPOCH_TO_NTP;

    *time = (uint64_t) (curr_ntp << 32u | (uint32_t) spec.tv_nsec);

    return 0;
}

clock_t bpf_clock(context_t *vm_ctx) {
    UNUSED(vm_ctx);
    return clock();
}


void ebpf_print(context_t *vm_ctx, const char *format, ...) {

    UNUSED(vm_ctx);

    va_list vars;
    va_start(vars, format);
    vfprintf(stderr, format, vars);
    va_end(vars);

}

/// memcpy IS TAKEN FROM
/// http://www.ethernut.de/api/memcpy_8c_source.html

/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
typedef int word;        /* "word" used for optimal copy speed */

#define    wsize    sizeof(word)
#define    wmask    (wsize - 1)

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */
void *ebpf_memcpy(context_t *vm_ctx, void *dst0, const void *src0, size_t length) {
    UNUSED(vm_ctx);
    char *dst = dst0;
    const char *src = src0;
    size_t t;

    if (length == 0 || dst == src)        /* nothing to do */
        goto done;

    /*
     * Macros: loop-t-times; and loop-t-times, t>0
     */
#define    TLOOP(s) if (t) TLOOP1(s)
#define    TLOOP1(s) do { s; } while (--t)

    if ((unsigned long) dst < (unsigned long) src) {
        /*
         * Copy forward.
         */
        t = (uintptr_t) src;    /* only need low bits */
        if ((t | (uintptr_t) dst) & wmask) {
            /*
             * Try to align operands.  This cannot be done
             * unless the low bits match.
             */
            if ((t ^ (uintptr_t) dst) & wmask || length < wsize)
                t = length;
            else
                t = wsize - (t & wmask);
            length -= t;
            TLOOP1(*dst++ = *src++);
        }
        /*
         * Copy whole words, then mop up any trailing bytes.
         */
        t = length / wsize;
        TLOOP(*(word *) dst = *(word *) src;
                      src += wsize;
                      dst += wsize);
        t = length & wmask;
        TLOOP(*dst++ = *src++);
    } else {
        /*
         * Copy backwards.  Otherwise essentially the same.
         * Alignment works as before, except that it takes
         * (t&wmask) bytes to align, not wsize-(t&wmask).
         */
        src += length;
        dst += length;
        t = (uintptr_t) src;
        if ((t | (uintptr_t) dst) & wmask) {
            if ((t ^ (uintptr_t) dst) & wmask || length <= wsize)
                t = length;
            else
                t &= wmask;
            length -= t;
            TLOOP1(*--dst = *--src);
        }
        t = length / wsize;
        TLOOP(src -= wsize;
                      dst -= wsize;
                      *(word *) dst = *(word *) src);
        t = length & wmask;
        TLOOP(*--dst = *--src);
    }
    done:
    return (dst0);
}


void set_error(context_t *vm_ctx, const char *reason, size_t len) {
    if (!reason) return;


    len = len < LENGTH_CONTEXT_ERROR ? len : LENGTH_CONTEXT_ERROR - 1;

    vm_ctx->error_status = 1; // the error originate from the code itself and not from the VM

    memset(vm_ctx->error, 0, sizeof(char) * LENGTH_CONTEXT_ERROR);
    strncpy(vm_ctx->error, reason, len);
    vm_ctx->error[LENGTH_CONTEXT_ERROR - 1] = 0;
}


void *bpf_get_args(context_t *vm_ctx, unsigned int arg_nb, bpf_full_args_t *args) {

    // fprintf(stderr, "Ptr ctx at %s call --> %p\n", __FUNCTION__, vm_ctx);

    bpf_args_t *check_args = get_args(args);
    if (!check_args) {
        fprintf(stderr, "Error in arguments (%s)\n", id_plugin_to_str(vm_ctx->p->plugin_id));
        return NULL;
    }
    if (arg_nb >= check_args->len) {
        return NULL;
    }

    if (check_args[arg_nb].kind == kind_ptr) {
        if(check_args[arg_nb].arg == NULL) {
            return NULL;
        }
    }

    uint8_t *ret_arg = bump_alloc(&vm_ctx->p->mem.heap.mp, args->args[arg_nb].len);
    if (ret_arg == NULL){
        return NULL;
    }
    memcpy(ret_arg, args->args[arg_nb].arg, args->args[arg_nb].len);

    return ret_arg;
}


static int in6addr_cmp(const struct in6_addr *addr1,
                       const struct in6_addr *addr2)
{
    size_t i;
    const uint8_t *p1, *p2;

    p1 = (const uint8_t *)addr1;
    p2 = (const uint8_t *)addr2;

    for (i = 0; i < sizeof(struct in6_addr); i++) {
        if (p1[i] > p2[i])
            return 1;
        else if (p1[i] < p2[i])
            return -1;
    }
    return 0;
}


int bpf_sockunion_cmp(context_t *vm_ctx, const struct sockaddr *su1, const struct sockaddr *su2) {
    UNUSED(vm_ctx);
    uint32_t ipsu1;
    uint32_t ipsu2;

    if (su1->sa_family > su2->sa_family) {
        return 1;
    }
    if (su1->sa_family < su2->sa_family) {
        return -1;
    }

    if (su1->sa_family == AF_INET) {

        ipsu1 = ntohl(((struct sockaddr_in *) su1)->sin_addr.s_addr);
        ipsu2 = ntohl(((struct sockaddr_in *) su2)->sin_addr.s_addr);

        if (ipsu1 == ipsu2)
            return 0;
        if (ipsu1 > ipsu2)
            return 1;
        else
            return -1;
    }
    if (su1->sa_family == AF_INET6) {
        return in6addr_cmp(&((struct sockaddr_in6 *) su1)->sin6_addr, &((struct sockaddr_in6 *) su2)->sin6_addr);
    }
    return 0;
}

void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    fprintf(stderr, "Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr,
            stack_ptr);
}
