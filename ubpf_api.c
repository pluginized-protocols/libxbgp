//
// Created by thomas on 4/11/18.
//

#include <libgen.h>
#include <linux/limits.h>
#include <sys/un.h>
#include <include/plugin_arguments.h>
#include "include/ebpf_mod_struct.h"
#include <json-c/json_object.h>
#include <ubpf_api.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "ubpf_context.h"

#include "include/tools_ubpf_api.h"
#include "include/global_info_str.h"
#include "bpf_plugin.h"
#include <unistd.h>

#include "stdarg.h"
#include "plugin_extra_configuration.h"
#include "url_parser.h"
#include "log.h"
#include "plugin_socket.h"
#include "static_injection.h"

#include <netinet/in.h>
#include <float.h>
#include <math.h>
#include <errno.h>
#include <wait.h>
#include <sys/stat.h>
#include <ffi.h>





uint16_t super_ntohs(context_t *ctx, uint16_t value) {
    ((void) (ctx));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((value & 0x00FFu) << 8u) |
            ((value & 0xFF00u) >> 8u));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}


uint32_t super_ntohl(context_t *ctx, uint32_t value) {
    ((void) (ctx));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((value & 0x000000FFu) << 24u) |
            ((value & 0x0000FF00u) << 8u) |
            ((value & 0x00FF0000u) >> 8u) |
            ((value & 0xFF000000u) >> 24u));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

uint64_t super_ntohll(context_t *ctx, uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (
            ((u_int64_t) (super_ntohl(ctx, (int) ((value << 32u) >> 32u))) << 32u) |
            (unsigned int) super_ntohl(ctx, ((int) (value >> 32u)))
    );
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

uint16_t super_htons(context_t *ctx __attribute__((unused)), uint16_t val) {
#if __BYTE_ORDER == __ORDER_LITTLE_ENDIAN__

    return (
            (((unsigned short) (val) & 0x00FFu)) << 8u |
            (((unsigned short) (val) & 0xFF00u) >> 8u)
    );
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#error unsupported endianness
#endif
}

uint32_t super_htonl(context_t *ctx __attribute__((unused)), uint32_t val) {
#if __BYTE_ORDER == __ORDER_LITTLE_ENDIAN__
    return (
            ((((unsigned long) (val) & 0x000000FFu)) << 24u) |
            ((((unsigned long) (val) & 0x0000FF00u)) << 8u) |
            ((((unsigned long) (val) & 0x00FF0000u)) >> 8u) |
            ((((unsigned long) (val) & 0xFF000000u)) >> 24u)
    );
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#error unsupported endianness
#endif
}

uint64_t super_htonll(context_t *ctx, uint64_t val) {
#if __BYTE_ORDER == __ORDER_LITTLE_ENDIAN__
    return (
            ((((uint64_t) super_htonl(ctx, val)) << 32u) + super_htonl(ctx, (val) >> 32u))
    );
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
#error unsupported endianness
#endif
}


int __super_log(UNUSED context_t *vm_ctx, const char *msg, struct vargs *args) {

    int i;
    ffi_cif CIF;
    ffi_type **types;
    void **values;

    if (*msg < 1 || *msg > 8) {
        // bad formatted msg, abort
        return 0;
    }

    types = (ffi_type **) malloc((args->nb_args + 1) * sizeof(ffi_type *));
    values = (void **) malloc((args->nb_args + 1) * sizeof(void *));

    // msg parameter of log_msg
    types[0] = &ffi_type_pointer;
    values[0] = &msg;

    for (i = 0; i < args->nb_args; i++) {
        switch (args->args[i].type) {
            case VT_S8:
                types[1 + i] = &ffi_type_sint8;
                values[1 + i] = &args->args[i].val.s8;
                break;
            case VT_U8:
                types[1 + i] = &ffi_type_uint8;
                values[1 + i] = &args->args[i].val.u8;
                break;
            case VT_S16:
                types[1 + i] = &ffi_type_sint16;
                values[1 + i] = &args->args[i].val.s16;
                break;
            case VT_U16:
                types[1 + i] = &ffi_type_uint16;
                values[1 + i] = &args->args[i].val.u16;
                break;
            case VT_S32:
                types[1 + i] = &ffi_type_sint32;
                values[1 + i] = &args->args[i].val.s32;
                break;
            case VT_U32:
                types[1 + i] = &ffi_type_uint32;
                values[1 + i] = &args->args[i].val.u32;
                break;
            case VT_S64:
                types[1 + i] = &ffi_type_sint64;
                values[1 + i] = &args->args[i].val.s64;
                break;
            case VT_U64:
                types[1 + i] = &ffi_type_sint64;
                values[1 + i] = &args->args[i].val.u64;
                break;
            case VT_FLOAT:
                types[1 + i] = &ffi_type_float;
                values[1 + i] = &args->args[i].val.fvalue;
                break;
            case VT_DOUBLE:
                types[1 + i] = &ffi_type_double;
                values[1 + i] = &args->args[i].val.dvalue;
                break;
            case VT_LONGDOUBLE:
                types[1 + i] = &ffi_type_longdouble;
                values[1 + i] = &args->args[i].val.ldvalue;
                break;
            case VT_POINTER:
                types[1 + i] = &ffi_type_pointer;
                values[1 + i] = &args->args[i].val.s8;
                break;
            case VT_UCHAR:
                types[1 + i] = &ffi_type_uchar;
                values[1 + i] = &args->args[i].val.uchar;
                break;
            case VT_SCHAR:
                types[1 + i] = &ffi_type_schar;
                values[1 + i] = &args->args[i].val.schar;
                break;
            case VT_USHORT:
                types[1 + i] = &ffi_type_ushort;
                values[1 + i] = &args->args[i].val.ushort;
                break;
            case VT_SSHORT:
                types[1 + i] = &ffi_type_sshort;
                values[1 + i] = &args->args[i].val.sshort;
                break;
            case VT_UINT:
                types[1 + i] = &ffi_type_uint;
                values[1 + i] = &args->args[i].val.uint;
                break;
            case VT_SINT:
                types[1 + i] = &ffi_type_sint;
                values[1 + i] = &args->args[i].val.sint;
                break;
            case VT_SLONG:
                types[1 + i] = &ffi_type_slong;
                values[1 + i] = &args->args[i].val.slong;
                break;
            case VT_ULONG:
                types[1 + i] = &ffi_type_ulong;
                values[1 + i] = &args->args[i].val.ulong;
                break;
            case VT_ULLONG:
                types[1 + i] = &ffi_type_uint64;
                values[1 + i] = &args->args[i].val.ullong;
                break;
            case VT_SLLONG:
                types[1 + i] = &ffi_type_sint64;
                values[1 + i] = &args->args[i].val.sllong;
                break;
            default:
                return 0;
        }
    }

    if (ffi_prep_cif_var(&CIF, FFI_DEFAULT_ABI, 1,
                         args->nb_args + 1, &ffi_type_void, types) == FFI_OK) {
        ffi_call(&CIF, FFI_FN(msg_log), NULL, values);

    }

    free(types);
    free(values);

    return 1;
}

void *__ctx_malloc(context_t *vm_ctx, size_t size) {
    return bump_alloc(&vm_ctx->p->mem.heap.mp, size);
}

void *__ctx_calloc(context_t *vm_ctx, size_t nmemb, size_t size) {
    return bump_calloc(&vm_ctx->p->mem.heap.mp, nmemb, size);
}

void *__ctx_realloc(UNUSED context_t *vm_ctx, UNUSED void *ptr, UNUSED size_t size) {
    return NULL; // we don't do that here
}

void __ctx_free(UNUSED context_t *vm_ctx, UNUSED void *ptr) {
    // bump alloc is a stack like alloc --> everything is removed after
    // the plugin call
    // my_free(&vm_ctx->p->heap.mp, ptr);
}

void *__ctx_shmnew(context_t *vm_ctx, key_t key, size_t size) {
    void *addr;
    addr = ubpf_shmnew(&vm_ctx->p->mem.shared_heap.smp, key, size);
    if (addr)
        memset(addr, 0, size);
    return addr;
}

void *__ctx_shmget(context_t *vm_ctx, key_t key) {
    return ubpf_shmget(&vm_ctx->p->mem.shared_heap.smp, key);
}

void __ctx_shmrm(context_t *vm_ctx, key_t key) {
    ubpf_shmrm(&vm_ctx->p->mem.shared_heap.smp, key);
}

int __get_time(UNUSED context_t *vm_ctx, struct timespec *spec) {

    memset(spec, 0, sizeof(*spec));

    if (clock_gettime(CLOCK_MONOTONIC, spec) != 0) {
        perror("Clock gettime");
        return -1;
    }

    return 0;
}

clock_t __bpf_clock(UNUSED context_t *vm_ctx) {
    return clock();
}


void __ebpf_print(UNUSED context_t *vm_ctx, const char *format, ...) {

    va_list vars;
    va_start(vars, format);
    vfprintf(stderr, format, vars);
    va_end(vars);

}

int __next(context_t *vm_ctx) {
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

int __ebpf_bvsnprintf(UNUSED context_t *ctx, char *buf, int size, const char *fmt, uintptr_t *args) {
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
void *__ebpf_memcpy(UNUSED context_t *vm_ctx, void *dst0, const void *src0, size_t length) {
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


void *__get_arg(context_t *vm_ctx, int type) {
    int i;
    uint8_t *ret_arg;
    // fprintf(stderr, "Ptr ctx at %s call --> %p\n", __FUNCTION__, vm_ctx);

    args_t *check_args = vm_ctx->args;
    if (!check_args) {
        return NULL;
    }

    for (i = 0; i < check_args->nargs; i++) {
        if (check_args->args[i].type == type) {
            ret_arg = bump_alloc(&vm_ctx->p->mem.heap.mp, check_args->args[i].len);
            if (!ret_arg) return NULL;
            memcpy(ret_arg, check_args->args[i].arg, check_args->args[i].len);
            return ret_arg;
        }
    }
    return NULL;
}


/*static int in6addr_cmp(const struct in6_addr *addr1,
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
}*/

void membound_fail(context_t *ctx __attribute__((unused)), uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    fprintf(stderr, "Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr,
            stack_ptr);
}


uint64_t __ebpf_sqrt(context_t *ctx __attribute__((unused)), uint64_t a, unsigned int precision) {

    double s_half;
    double s;
    uint64_t res;

    if (a >= DBL_MAX) return 0;

    s = a;
    s_half = sqrt(s);
    res = s_half * pow(10, precision);

    return res;
}

int __ebpf_memcmp(context_t *ctx UNUSED, const void *s1, const void *s2, size_t n) {

    return memcmp(s1, s2, n);

}

int __get_extra_info_value(context_t *ctx UNUSED, struct global_info *info, void *buf, size_t len_buf) {
    return extra_info_copy_data(info, buf, len_buf);
}

int __get_extra_info_lst_idx(context_t *ctx UNUSED, struct global_info *info, int arr_idx, struct global_info *value) {
    return get_info_lst_idx(info, arr_idx, value);
}

int __get_extra_info_dict(context_t *ctx UNUSED, struct global_info *info, const char *key, struct global_info *value) {
    if (!key) return -1;
    return get_info_dict(info, key, value);
}

int __get_extra_info(context_t *ctx UNUSED, const char *key, struct global_info *info) {
    return get_global_info(key, info);
}

int __ebpf_inet_ntop(context_t *ctx UNUSED, uint8_t *ipaddr, int type, char *buf, size_t len) {

    struct in_addr ipv4;
    struct in6_addr ipv6;
    void *ip;

    switch (type) {
        case AF_INET:
            ipv4.s_addr = *(uint32_t *) ipaddr;
            ip = &ipv4;
            break;
        case AF_INET6:
            memcpy(&ipv6, ipaddr, sizeof(ipv6));
            ip = &ipv6;
            break;
        default:
            return -1;
    }

    if (!inet_ntop(type, ip, buf, len)) return -1;

    return 0;
}

int __ebpf_inet_pton(UNUSED context_t *ctx, int af, const char *src, void *dst, size_t buf_len) {
    int s;
    size_t min_len;
    unsigned char buf[sizeof(struct in6_addr)];

    switch (af) {
        case AF_INET:
            min_len = sizeof(struct in_addr);
            break;
        case AF_INET6:
            min_len = sizeof(struct in6_addr);
            break;
        default:
            return -1;
    }

    if (buf_len < min_len) return -1;

    s = inet_pton(af, src, buf);

    if (s <= 0) {
        return -1;
    }
    memcpy(dst, buf, min_len);
    return 0;
}


#define safe_snprintf(offset, dst, maxlen, format, ...) ({      \
    int __ret__ = 0;                                            \
    unsigned int written_len__;                                 \
    written_len__ = snprintf(dst, maxlen, format, __VA_ARGS__); \
    if (written_len__ <= maxlen){                               \
        __ret__ = 1;                                            \
    }                                                           \
    offset += written_len__;                                    \
    dst += written_len__;                                       \
    __ret__;                                                    \
})

static inline int build_src_rsync(struct parsed_url *url, char *buf, size_t len) {
    unsigned int offset = 0;
    char *str = buf;

    if (url->username) {
        if (!safe_snprintf(offset, str, len - offset, "%s", url->username)) { return -1; }
    }

    if (!url->host) { return -1; }

    if (!safe_snprintf(offset, str, len - offset, url->username != NULL ? "@%s" : "%s", url->host)) { return -1; }

    if (!url->path) { return -1; }

    if (!safe_snprintf(offset, str, len - offset, ":%s", url->path)) { return -1; }

    return 0;
}

int fetch_file(context_t *ctx UNUSED, char *url, char *dest) {
    pid_t pid;
    int ret, wstatus;
    char src[PATH_MAX];
    struct parsed_url *p_url;
    char *id_file;
    char ssh_info[PATH_MAX];
    char *mod_path;
    int prev_size;
    int i;

    p_url = parse_url(url);
    if (!p_url) {
        fprintf(stderr, "Unable to parse url %s\n", url);
        return -1;
    }

    if (p_url->path[0] != '/') {
        prev_size = strnlen(p_url->path, PATH_MAX);
        mod_path = realloc(p_url->path, prev_size + 2); // 1 for the extra '/' + 1 for null byte at the end
        if (mod_path == NULL) {
            perror("realloc");
            return -1;
        }

        for (i = prev_size; i > 0; i--) {
            mod_path[i] = mod_path[i - 1];
        }
        mod_path[0] = '/';
        mod_path[prev_size + 1] = 0;
        p_url->path = mod_path;
    }

    memset(src, 0, sizeof(src));
    memset(ssh_info, 0, sizeof(ssh_info));
    if (build_src_rsync(p_url, src, PATH_MAX - 1) == -1) return -1;

    id_file = getenv("UBPF_IDENTITY_FILE");
    if (id_file) {
        snprintf(ssh_info, PATH_MAX,
                 "ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", id_file);
    } else {
        snprintf(ssh_info, PATH_MAX,
                 "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null");
    }

    // call rsync to fetch the file locally
    pid = fork();

    if (pid == -1) { // unable to fork
        perror("Unable to fork");
    } else if (pid == 0) { // in the child
        const char *const argv[] = {
                "rsync", "--archive", "-hh",
                "--partial", "--modify-window=2",
                "-e", ssh_info,
                src, dest,
                NULL
        };
        close(STDERR_FILENO);
        close(STDIN_FILENO);
        if (execve("/usr/bin/rsync", argv, NULL) == -1) { exit(EXIT_FAILURE); }
    }

    ret = waitpid(pid, &wstatus, 0);
    if (ret == -1) {
        perror("waitpid failed");
    }

    if (WIFEXITED(wstatus)) {
        if (WEXITSTATUS(wstatus) == EXIT_SUCCESS) {
            return 0;
        } else {
            return -1;
        }
    } else if (WIFSIGNALED(wstatus)) {
        return -1;
    }
    return 0;
}


int __sk_open(UNUSED context_t *ctx, sk_type_t proto, int af, const struct sockaddr *addr, socklen_t len) {
    return ctx_open(proto, af, addr, len);
}

int __sk_write(UNUSED context_t *ctx, int sfd, const void *buf, size_t len) {
    return ctx_write(sfd, buf, len);
}

int __sk_read(UNUSED context_t *ctx, int sfd, void *buf, size_t len) {
    return ctx_read(sfd, buf, len);
}

int __sk_close(UNUSED context_t *ctx, int sfd) {
    return ctx_close(sfd);
}


struct inject_pluglet_args {
    struct {
        const uint8_t *bytecode;
        size_t len;
    } elf;

    struct {
        int extra;
        int shared;
    } mem;

    const char *plugin_name;
    size_t plugin_name_len;

    const char *insertion_point_name;
    size_t insertion_point_name_len;

    const char *this_vm_name;
    size_t this_vm_name_len;

    int jit;
    int anchor;
    int seq;
};

int inject_pluglet(context_t *ctx, struct inject_pluglet_args *arg) {
    int insertion_point_id;
    int anchor_id;

    if (!arg) return -1;

    // begin check if the request is valid
    insertion_point_id =
            str_to_id_insertion_point(ctx->insertion_point_info,
                                      arg->insertion_point_name,
                                      arg->insertion_point_name_len);
    switch (arg->anchor) {
        case BPF_PRE:
        case BPF_REPLACE:
        case BPF_POST:
            anchor_id = arg->anchor;
            break;
        default:
            return -1;
    }

    if (insertion_point_id == -1) return -1;
    if (arg->seq <= 0) return -1;


    // end check request
    //add_extension_code(arg)

    return -1;
}