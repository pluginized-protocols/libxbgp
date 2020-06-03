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
#include "include/global_info_str.h"
#include "bpf_plugin.h"
#include <unistd.h>

#include "stdarg.h"
#include "plugin_extra_configuration.h"

#include <netinet/in.h>
#include <float.h>
#include <math.h>
#include <errno.h>


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
    msgid = msgget(key, 0666u | (unsigned int) IPC_CREAT);

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

int send_ipc_msg(UNUSED context_t *ctx, ebpf_message_t *msg) {

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

    if (len > UINT32_MAX) {
        fprintf(stderr, "len failed\n");
        return -1;
    }

    if (send_all(sock_fd, &len, sizeof(uint32_t)) < 0)
        return 0;
    if (send_all(sock_fd, &_type, sizeof(uint32_t)) < 0)
        return 0;
    if (send_all(sock_fd, data, len) < 0)
        return 0;

    return 1;
}

int send_to_monitor(UNUSED context_t *vm_ctx, const void *data, size_t len, unsigned int type) {

    if (type == 0) return 0;

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

void *ctx_realloc(UNUSED context_t *vm_ctx, UNUSED void *ptr, UNUSED size_t size) {
    return NULL; // we don't do that here
}

void ctx_free(UNUSED context_t *vm_ctx, UNUSED void *ptr) {
    // bump alloc is a stack like alloc --> everything is removed after
    // the plugin call
    // my_free(&vm_ctx->p->heap.mp, ptr);
}

void *ctx_shmnew(context_t *vm_ctx, key_t key, size_t size) {
    void *addr;
    addr = ubpf_shmnew(&vm_ctx->p->mem.shared_heap.smp, key, size);
    if (addr)
        memset(addr, 0, size);
    return addr;
}

void *ctx_shmget(context_t *vm_ctx, key_t key) {
    return ubpf_shmget(&vm_ctx->p->mem.shared_heap.smp, key);
}

void ctx_shmrm(context_t *vm_ctx, key_t key) {
    ubpf_shmrm(&vm_ctx->p->mem.shared_heap.smp, key);
}

int get_time(UNUSED context_t *vm_ctx, struct timespec *spec) {

    memset(spec, 0, sizeof(*spec));

    if (clock_gettime(CLOCK_MONOTONIC, spec) != 0) {
        perror("Clock gettime");
        return -1;
    }

    return 0;
}

clock_t bpf_clock(UNUSED context_t *vm_ctx) {
    return clock();
}


void ebpf_print(UNUSED context_t *vm_ctx, const char *format, ...) {

    va_list vars;
    va_start(vars, format);
    vfprintf(stderr, format, vars);
    va_end(vars);

}

int next(context_t *vm_ctx) {
    return run_replace_next_replace_function(vm_ctx);
}


/* The following piece of code is taken and adapted from bird routing project */
/* ~~~ BEGIN BIRD CODE ~~~*/

#define ZEROPAD    1u        /* pad with zero */
#define SIGN    2u        /* unsigned/signed long */
#define PLUS    4u        /* show plus */
#define SPACE    8u        /* space if plus */
#define LEFT    16u        /* left justified */
#define SPECIAL    32u        /* 0x */
#define LARGE    64u        /* use 'ABCDEF' instead of 'abcdef' */

#define S_    * (uint64_t) 1000000
#define MS_    * (uint64_t) 1000
#define US_    * (uint64_t) 1
#define TO_S    /1000000
#define TO_MS    /1000
#define TO_US    /1

#define S    S_
#define MS    MS_
#define US    US_
#define NS    /1000

#define is_digit(c)    ((c) >= '0' && (c) <= '9')

static inline int skip_atoi(const char **s) {
    int i = 0;

    while (is_digit(**s))
        i = i * 10 + *((*s)++) - '0';
    return i;
}

static inline char *
number(char *str, uint64_t num, uint base, int size, int precision, int type, int remains) {
    char c, sign, tmp[66];
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i;

    if (size >= 0 && (remains -= size) < 0)
        return NULL;
    if (type & LARGE)
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (type & LEFT)
        type &= ~ZEROPAD;
    if (base < 2 || base > 36)
        return 0;
    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN) {
        if (num > (uint64_t) INT64_MAX) {
            sign = '-';
            num = -num;
            size--;
        } else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
    }
    if (type & SPECIAL) {
        if (base == 16)
            size -= 2;
        else if (base == 8)
            size--;
    }
    i = 0;
    if (num == 0)
        tmp[i++] = '0';
    else
        while (num != 0) {
            uint res = num % base;
            num = num / base;
            tmp[i++] = digits[res];
        }
    if (i > precision)
        precision = i;
    size -= precision;
    if (size < 0 && -size > remains)
        return NULL;
    if (!(type & (ZEROPAD + LEFT)))
        while (size-- > 0)
            *str++ = ' ';
    if (sign)
        *str++ = sign;
    if (type & SPECIAL) {
        if (base == 8)
            *str++ = '0';
        else if (base == 16) {
            *str++ = '0';
            *str++ = digits[33];
        }
    }
    if (!(type & LEFT))
        while (size-- > 0)
            *str++ = c;
    while (i < precision--)
        *str++ = '0';
    while (i-- > 0)
        *str++ = tmp[i];
    while (size-- > 0)
        *str++ = ' ';
    return str;
}

int ebpf_bvsnprintf(UNUSED context_t *ctx, char *buf, int size, const char *fmt, uintptr_t *args) {
    int curr_args;
    int len, i;
    uint64_t num;
    uint base;
    int64_t t;
    int64_t t1, t2;
    char *str, *start;
    const char *s;

    int flags;        /* flags to number() */

    int field_width;    /* width of output field */
    int precision;        /* min. # of digits for integers; max
				   number of chars for from string */
    int qualifier;        /* 'h' or 'l' for integer fields */

    // nb_args = args[0];
    curr_args = 1; // 0 is the number of args

    for (start = str = buf; *fmt; ++fmt, size -= (str - start), start = str) {
        if (*fmt != '%') {
            if (!size)
                return -1;
            *str++ = *fmt;
            continue;
        }

        /* process flags */
        flags = 0;
        repeat:
        ++fmt;        /* this also skips first '%' */
        switch (*fmt) {
            case '-':
                flags |= LEFT;
                goto repeat;
            case '+':
                flags |= PLUS;
                goto repeat;
            case ' ':
                flags |= SPACE;
                goto repeat;
            case '#':
                flags |= SPECIAL;
                goto repeat;
            case '0':
                flags |= ZEROPAD;
                goto repeat;
        }

        /* get field width */
        field_width = -1;
        if (is_digit(*fmt))
            field_width = skip_atoi(&fmt);
        else if (*fmt == '*') {
            ++fmt;
            /* it's the next argument */
            field_width = (int) args[curr_args++];//va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }

        /* get the precision */
        precision = -1;
        if (*fmt == '.') {
            ++fmt;
            if (is_digit(*fmt))
                precision = skip_atoi(&fmt);
            else if (*fmt == '*') {
                ++fmt;
                /* it's the next argument */
                precision = (int) args[curr_args++];
            }
            if (precision < 0)
                precision = 0;
        }

        /* get the conversion qualifier */
        qualifier = -1;
        if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
            qualifier = *fmt;
            ++fmt;
        }

        /* default base */
        base = 10;

        if (field_width > size)
            return -1;
        switch (*fmt) {
            case 'c':
                if (!(flags & LEFT))
                    while (--field_width > 0)
                        *str++ = ' ';
                *str++ = (uint8_t) args[curr_args++];
                while (--field_width > 0)
                    *str++ = ' ';
                continue;

            case 'm':
                if (flags & SPECIAL) {
                    if (!errno)
                        continue;
                    if (size < 2)
                        return -1;
                    *str++ = ':';
                    *str++ = ' ';
                    start += 2;
                    size -= 2;
                }
                s = strerror(errno);
                goto str;
            case 's':
                s = (char *) args[curr_args++];
                if (!s)
                    s = "<NULL>";

            str:
                len = strnlen(s, size); // prevent buffer overflow when wrong announced format
                if (precision >= 0 && len > precision)
                    len = precision;
                if (len > size)
                    return -1;

                if (!(flags & LEFT))
                    while (len < field_width--)
                        *str++ = ' ';
                for (i = 0; i < len; ++i)
                    *str++ = *s++;
                while (len < field_width--)
                    *str++ = ' ';
                continue;

                /*case 'V': { // put this case in standby ! (not really a good feature I guess)
                    const char *vfmt = (const char *) args[curr_args++];
                    va_list *vargs = va_arg(args, va_list *);
                    int res = bvsnprintf(str, size, vfmt, *vargs);
                    if (res < 0)
                        return -1;
                    str += res;
                    size -= res;
                    continue;
                }*/

            case 'p':
                if (field_width == -1) {
                    field_width = 2 * sizeof(void *);
                    flags |= ZEROPAD;
                }
                str = number(str, args[curr_args++], 16,
                             field_width, precision, flags, size);
                if (!str)
                    return -1;
                continue;

            case 'n':
                if (qualifier == 'l') {
                    int64_t *ip = (int64_t *) args[curr_args++];
                    *ip = (str - buf);
                } else {
                    int *ip = (int *) args[curr_args++];
                    *ip = (str - buf);
                }
                continue;


            case 't':
                t = (uint64_t) args[curr_args++];
                t1 = t TO_S;
                t2 = t - t1 S;

                if (precision < 0)
                    precision = 3;

                if (precision > 6)
                    precision = 6;

                /* Compute field_width for second part */
                if ((precision > 0) && (field_width > 0))
                    field_width -= (1 + precision);

                if (field_width < 0)
                    field_width = 0;

                /* Print seconds */
                flags |= SIGN;
                str = number(str, (uint64_t) t1, 10, field_width, 0, flags, size);
                if (!str)
                    return -1;

                if (precision > 0) {
                    size -= (str - start);
                    start = str;

                    if ((1 + precision) > size)
                        return -1;

                    /* Convert microseconds to requested precision */
                    for (i = precision; i < 6; i++)
                        t2 /= 10;

                    /* Print sub-seconds */
                    *str++ = '.';
                    str = number(str, (uint64_t) t2, 10, precision, 0, ZEROPAD, size - 1);
                    if (!str)
                        return -1;
                }
                goto done;

                /* integer number formats - set up the flags and "break" */
            case 'o':
                base = 8;
                break;

            case 'X':
                flags |= LARGE;
                /* fallthrough */
            case 'x':
                base = 16;
                break;

            case 'd':
            case 'i':
                flags |= SIGN;
            case 'u':
                break;

            default:
                if (size < 2)
                    return -1;
                if (*fmt != '%')
                    *str++ = '%';
                if (*fmt)
                    *str++ = *fmt;
                else
                    --fmt;
                continue;
        }
        if (flags & SIGN) {
            /* Conversions valid per ISO C99 6.3.1.3 (2) */
            if (qualifier == 'l')
                num = (uint64_t) args[curr_args++];
            else if (qualifier == 'h')
                num = (uint64_t) (
                        short) args[curr_args++];
            else
                num = (uint64_t) args[curr_args++];
        } else {
            if (qualifier == 'l')
                num = (uint64_t) args[curr_args++];
            else if (qualifier == 'h')
                num = (unsigned short) args[curr_args++];
            else
                num = (uint) args[curr_args++];
        }
        str = number(str, num, base, field_width, precision, flags, size);
        if (!str)
            return -1;
        done:;
    }
    if (!size)
        return -1;
    *str = '\0';
    return str - buf;
}

/* ~~~ END BIRD CODE ~~~*/

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
void *ebpf_memcpy(UNUSED context_t *vm_ctx, void *dst0, const void *src0, size_t length) {
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
        TLOOP(*(word *) dst = *(const word *) src;
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
                      *(word *) dst = *(const word *) src);
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
    if (arg_nb >= args->nargs) {
        return NULL;
    }

    if (check_args[arg_nb].kind == kind_hidden) {
        return NULL;
    }

    if (check_args[arg_nb].kind == kind_ptr) {
        if (check_args[arg_nb].arg == NULL) {
            return NULL;
        }
    }

    uint8_t *ret_arg = bump_alloc(&vm_ctx->p->mem.heap.mp, args->args[arg_nb].len);
    if (ret_arg == NULL) {
        return NULL;
    }
    memcpy(ret_arg, args->args[arg_nb].arg, args->args[arg_nb].len);

    return ret_arg;
}


static int in6addr_cmp(const struct in6_addr *addr1,
                       const struct in6_addr *addr2) {
    size_t i;
    const uint8_t *p1, *p2;

    p1 = (const uint8_t *) addr1;
    p2 = (const uint8_t *) addr2;

    for (i = 0; i < sizeof(struct in6_addr); i++) {
        if (p1[i] > p2[i])
            return 1;
        else if (p1[i] < p2[i])
            return -1;
    }
    return 0;
}


int bpf_sockunion_cmp(UNUSED context_t *vm_ctx, const struct sockaddr *su1, const struct sockaddr *su2) {
    uint32_t ipsu1;
    uint32_t ipsu2;

    if (su1->sa_family > su2->sa_family) {
        return 1;
    }
    if (su1->sa_family < su2->sa_family) {
        return -1;
    }

    if (su1->sa_family == AF_INET) {

        ipsu1 = ntohl(((const struct sockaddr_in *) su1)->sin_addr.s_addr);
        ipsu2 = ntohl(((const struct sockaddr_in *) su2)->sin_addr.s_addr);

        if (ipsu1 == ipsu2)
            return 0;
        if (ipsu1 > ipsu2)
            return 1;
        else
            return -1;
    }
    if (su1->sa_family == AF_INET6) {
        return in6addr_cmp(&((const struct sockaddr_in6 *) su1)->sin6_addr,
                           &((const struct sockaddr_in6 *) su2)->sin6_addr);
    }
    return 0;
}

void membound_fail(context_t *ctx __attribute__((unused)), uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    fprintf(stderr, "Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr,
            stack_ptr);
}


uint64_t ebpf_sqrt(context_t *ctx __attribute__((unused)), uint64_t a, unsigned int precision) {

    double s_half;
    double s;
    uint64_t res;

    if (a >= DBL_MAX) return 0;

    s = a;
    s_half = sqrt(s);
    res = s_half * pow(10, precision);

    return res;
}

int ebpf_memcmp(context_t *ctx UNUSED, const void *s1, const void *s2, size_t n) {

    return memcmp(s1, s2, n);

}

int get_extra_info_value(context_t *ctx UNUSED, struct global_info *info, void *buf, size_t len_buf) {
    return extra_info_copy_data(info, buf, len_buf);
}

int get_extra_info_lst_idx(context_t *ctx UNUSED, struct global_info *info, int arr_idx, struct global_info *value) {
    return get_info_lst_idx(info, arr_idx, value);
}

int get_extra_info(context_t *ctx UNUSED, const char *key, struct global_info *info) {
    return get_global_info(key, info);
}