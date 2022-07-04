//
// Created by thomas on 4/11/18.
//

#include <linux/limits.h>
#include <sys/un.h>
#include <include/plugin_arguments.h>
#include "include/ebpf_mod_struct.h"
#include <ubpf_api.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include "include/tools_ubpf_api.h"
#include "include/plugin_arguments.h"
#include "bpf_plugin.h"
#include <unistd.h>

#include "plugin_extra_configuration.h"
#include "url_parser.h"
#include "log.h"
#include "plugin_socket.h"
#include "static_injection.h"
#include "evt_plugins.h"

#include <netinet/in.h>
#include <float.h>
#include <math.h>
#include <errno.h>
#include <wait.h>
#include <sys/stat.h>
#include <ffi.h>
#include "context_function.h"

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

static def_fun_api(super_ntohs, uint16_t, *(uint16_t *) ARGS[0]);


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

static def_fun_api(super_ntohl, uint32_t, *(uint32_t *) ARGS[0]);

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

static def_fun_api(super_ntohll, uint64_t, *(uint64_t *) ARGS[0])

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

static def_fun_api(super_htons, uint64_t, *(uint16_t *) ARGS[0])

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

static def_fun_api(super_htonl, uint64_t, *(uint32_t *) ARGS[0])

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

static def_fun_api(super_htonll, uint64_t, *(uint64_t *) ARGS[0])


static inline int fill_variadic_arguments(ffi_type **types, void **values, struct vargs *args) {
    int i;

    for (i = 0; i < args->nb_args; i++) {
        switch (args->args[i].type) {
            case VT_S8:
                types[i] = &ffi_type_sint8;
                values[i] = &args->args[i].val.s8;
                break;
            case VT_U8:
                types[i] = &ffi_type_uint8;
                values[i] = &args->args[i].val.u8;
                break;
            case VT_S16:
                types[i] = &ffi_type_sint16;
                values[i] = &args->args[i].val.s16;
                break;
            case VT_U16:
                types[i] = &ffi_type_uint16;
                values[i] = &args->args[i].val.u16;
                break;
            case VT_S32:
                types[i] = &ffi_type_sint32;
                values[i] = &args->args[i].val.s32;
                break;
            case VT_U32:
                types[i] = &ffi_type_uint32;
                values[i] = &args->args[i].val.u32;
                break;
            case VT_S64:
                types[i] = &ffi_type_sint64;
                values[i] = &args->args[i].val.s64;
                break;
            case VT_U64:
                types[i] = &ffi_type_sint64;
                values[i] = &args->args[i].val.u64;
                break;
            case VT_FLOAT:
                types[i] = &ffi_type_float;
                values[i] = &args->args[i].val.fvalue;
                break;
            case VT_DOUBLE:
                types[i] = &ffi_type_double;
                values[i] = &args->args[i].val.dvalue;
                break;
            case VT_LONGDOUBLE:
                types[i] = &ffi_type_longdouble;
                values[i] = &args->args[i].val.ldvalue;
                break;
            case VT_POINTER:
                types[i] = &ffi_type_pointer;
                values[i] = &args->args[i].val.s8;
                break;
            case VT_UCHAR:
                types[i] = &ffi_type_uchar;
                values[i] = &args->args[i].val.uchar;
                break;
            case VT_SCHAR:
                types[i] = &ffi_type_schar;
                values[i] = &args->args[i].val.schar;
                break;
            case VT_USHORT:
                types[i] = &ffi_type_ushort;
                values[i] = &args->args[i].val.ushort;
                break;
            case VT_SSHORT:
                types[i] = &ffi_type_sshort;
                values[i] = &args->args[i].val.sshort;
                break;
            case VT_UINT:
                types[i] = &ffi_type_uint;
                values[i] = &args->args[i].val.uint;
                break;
            case VT_SINT:
                types[i] = &ffi_type_sint;
                values[i] = &args->args[i].val.sint;
                break;
            case VT_SLONG:
                types[i] = &ffi_type_slong;
                values[i] = &args->args[i].val.slong;
                break;
            case VT_ULONG:
                types[i] = &ffi_type_ulong;
                values[i] = &args->args[i].val.ulong;
                break;
            case VT_ULLONG:
                types[i] = &ffi_type_uint64;
                values[i] = &args->args[i].val.ullong;
                break;
            case VT_SLLONG:
                types[i] = &ffi_type_sint64;
                values[i] = &args->args[i].val.sllong;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

static def_fun_api(super_log, int, *(const char **) ARGS[0], *(struct vargs **) ARGS[1])

int super_log(UNUSED context_t *vm_ctx, const char *msg, struct vargs *args) {
    int ret_val = 0;
    ffi_cif CIF;
    ffi_type **types = NULL;
    void **values = NULL;

    if (*msg < 1 || *msg > 8) {
        // bad formatted msg, abort
        return 0;
    }

    types = (ffi_type **) malloc((args->nb_args + 1) * sizeof(ffi_type *));
    values = (void **) malloc((args->nb_args + 1) * sizeof(void *));

    if (!types || !values) {
        goto end;
    }

    // msg parameter of log_msg
    types[0] = &ffi_type_pointer;
    values[0] = &msg;

    // get variadic arguments contained in args
    if (fill_variadic_arguments(types + 1, values + 1, args) != 0) {
        goto end;
    }

    if (ffi_prep_cif_var(&CIF, FFI_DEFAULT_ABI, 1,
                         args->nb_args + 1, &ffi_type_void, types) == FFI_OK) {
        ffi_call(&CIF, FFI_FN(msg_log), NULL, values);

    } else {
        goto end;
    }

    /* everything went well so far */
    ret_val = 1;

    end:
    if (types) free(types);
    if (values) free(values);
    return ret_val;
}

static def_fun_api(ctx_malloc, void *, *(uint64_t *) ARGS[0])

void *ctx_malloc(context_t *vm_ctx, size_t size) {
    return mem_alloc(&vm_ctx->p->mem.mgr_heap, size);
}

static def_fun_api(ctx_calloc, void *, *(uint64_t *) ARGS[0], *(uint64_t *) ARGS[1])

void *ctx_calloc(context_t *vm_ctx, uint64_t nmemb, uint64_t size) {
    void *ptr;
    ptr = ctx_malloc(vm_ctx, nmemb * size);

    if (!ptr) return NULL;
    memset(ptr, 0, nmemb * size);
    return ptr;
}

static def_fun_api(ctx_realloc, void *, *(void **) ARGS[0], *(uint64_t *) ARGS[1])

void *ctx_realloc(context_t *vm_ctx, void *ptr, uint64_t size) {
    return mem_realloc(&vm_ctx->p->mem.mgr_heap, ptr, size);
}

static def_fun_api_void(ctx_free, *(void **) ARGS[0])

void ctx_free(UNUSED context_t *vm_ctx, UNUSED void *ptr) {
    mem_free(&vm_ctx->p->mem.mgr_heap, ptr);
}

static def_fun_api(ctx_shmnew, void *, *(key_t *) ARGS[0], *(uint64_t *) ARGS[1])

void *ctx_shmnew(context_t *vm_ctx, key_t key, uint64_t size) {
    void *addr;
    addr = shared_new(&vm_ctx->p->mem.mgr_shared_heap,
                      &vm_ctx->p->mem.shared_blocks, key, size);
    if (addr)
        memset(addr, 0, size);
    return addr;
}

static def_fun_api(ctx_shmget, void *, *(key_t *) ARGS[0])

void *ctx_shmget(context_t *vm_ctx, key_t key) {
    return shared_get(&vm_ctx->p->mem.mgr_shared_heap,
                      &vm_ctx->p->mem.shared_blocks, key);
}

static def_fun_api_void(ctx_shmrm, *(key_t *) ARGS[0])

void ctx_shmrm(context_t *vm_ctx, key_t key) {
    shared_rm(&vm_ctx->p->mem.mgr_shared_heap,
              &vm_ctx->p->mem.shared_blocks, key);
}

static def_fun_api(get_time, int, *(struct timespec **) ARGS[0])

int get_time(UNUSED context_t *vm_ctx, struct timespec *spec) {

    memset(spec, 0, sizeof(*spec));

    if (clock_gettime(CLOCK_MONOTONIC, spec) != 0) {
        perror("Clock gettime");
        return -1;
    }

    return 0;
}

static def_fun_api(get_realtime, int, *(struct timespec **) ARGS[0]);

int get_realtime(context_t *vm_ctx UNUSED, struct timespec *spec) {

    if (!spec) return -1;

    if (clock_gettime(CLOCK_REALTIME, spec) != 0) {
        perror("Clock gettime");
        return -1;
    }
    return 0;
}

static def_fun_api(ebpf_print_intern, int, *(const char **) ARGS[0], *(struct vargs **) ARGS[1])

int ebpf_print_intern(UNUSED context_t *vm_ctx, const char *format, struct vargs *args) {
    ffi_cif CIF;
    ffi_type **types = NULL;
    void **values = NULL;
    int rvalue = 0;

    types = malloc((args->nb_args + 1) * sizeof(ffi_type *));
    values = malloc((args->nb_args + 1) * sizeof(void *));

    if (!values || !types) goto end;

    /* printf 1st argument */
    types[0] = &ffi_type_pointer;
    values[0] = &format;

    if (fill_variadic_arguments(types + 1, values + 1, args) != 0) {
        goto end;
    }

    if (ffi_prep_cif_var(&CIF, FFI_DEFAULT_ABI, 1,
                         args->nb_args + 1, &ffi_type_sint, types) == FFI_OK) {
        ffi_call(&CIF, FFI_FN(printf), &rvalue, values);
    } else {
        goto end;
    }

    end:
    if (types) free(types);
    if (values) free(values);
    return rvalue;
}

static def_fun_api(next, int)

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

static def_fun_api(ebpf_bvsnprintf, int, *(char **) ARGS[0], *(int *) ARGS[1], *(const char **) ARGS[2],
            *(uintptr_t **) ARGS[3])

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

static def_fun_api(ebpf_memcpy, void *, *(void **) ARGS[0], *(const void **) ARGS[1], *(uint64_t *) ARGS[2])

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */
void *ebpf_memcpy(UNUSED context_t *vm_ctx, void *dst0, const void *src0, uint64_t length) {
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


static def_fun_api(get_arg, void *, *(int *) ARGS[0])

void *get_arg(context_t *vm_ctx, int type) {
    int i;
    uint8_t *ret_arg;
    // fprintf(stderr, "Ptr ctx at %s call --> %p\n", __FUNCTION__, vm_ctx);

    args_t *check_args = vm_ctx->args;
    if (!check_args) {
        return NULL;
    }

    for (i = 0; i < check_args->nargs; i++) {
        if (check_args->args[i].type == type) {
            ret_arg = mem_alloc(&vm_ctx->p->mem.mgr_heap, check_args->args[i].len);
            if (!ret_arg) return NULL;
            memcpy(ret_arg, check_args->args[i].arg, check_args->args[i].len);
            return ret_arg;
        }
    }
    return NULL;
}

static def_fun_api_void(membound_fail, *(uint64_t *) ARGS[0], *(uint64_t *) ARGS[1], *(uint64_t *) ARGS[2])

void membound_fail(context_t *ctx __attribute__((unused)), uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    fprintf(stderr, "Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr,
            stack_ptr);
}

static def_fun_api(ebpf_sqrt, uint64_t, *(uint64_t *) ARGS[0], *(unsigned int *) ARGS[2])

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

static def_fun_api(ebpf_memcmp, int, *(const void **) ARGS[0], *(const void **) ARGS[1], *(uint64_t *) ARGS[2])

int ebpf_memcmp(context_t *ctx UNUSED, const void *s1, const void *s2, uint64_t n) {
    return memcmp(s1, s2, n);
}

static def_fun_api(get_extra_info_value, int, *(struct global_info **) ARGS[0], *(void **) ARGS[1],
                   *(uint64_t *) ARGS[2])

int get_extra_info_value(context_t *ctx UNUSED, struct global_info *info, void *buf, uint64_t len_buf) {
    return extra_info_copy_data(info, buf, len_buf);
}

static def_fun_api(get_extra_info_lst_idx, int, *(struct global_info **) ARGS[0], *(int *) ARGS[1],
                   *(struct global_info **) ARGS[2])

int get_extra_info_lst_idx(context_t *ctx UNUSED, struct global_info *info, int arr_idx, struct global_info *value) {
    return get_info_lst_idx(info, arr_idx, value);
}

static def_fun_api(get_extra_info_dict, int, *(struct global_info **) ARGS[0], *(const char **) ARGS[1],
                   *(struct global_info **) ARGS[2])

int get_extra_info_dict(context_t *ctx UNUSED, struct global_info *info, const char *key, struct global_info *value) {
    if (!key) return -1;
    return get_info_dict(info, key, value);
}

static def_fun_api(get_extra_info, int, *(const char **) ARGS[0], *(struct global_info **) ARGS[1])

int get_extra_info(context_t *ctx UNUSED, const char *key, struct global_info *info) {
    return get_global_info(key, info);
}

static def_fun_api(ebpf_inet_ntop, int, *(uint8_t **) ARGS[0], *(int *) ARGS[1], *(char **) ARGS[2],
                   *(uint64_t *) ARGS[3])

int ebpf_inet_ntop(context_t *ctx UNUSED, uint8_t *ipaddr, int type, char *buf, uint64_t len) {
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

static def_fun_api(ebpf_inet_pton, int, *(int *) ARGS[0], *(const char **) ARGS[1], *(void **) ARGS[2],
                   *(uint64_t *) ARGS[3])

int ebpf_inet_pton(UNUSED context_t *ctx, int af, const char *src, void *dst, uint64_t buf_len) {
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

static def_fun_api(fetch_file, int, *(char **) ARGS[0], *(const char **) ARGS[1])

int fetch_file(context_t *ctx UNUSED, char *url, const char *dest) {
    pid_t pid;
    int ret, wstatus;
    char src[PATH_MAX];
    struct parsed_url *p_url;
    char *id_file;
    char ssh_info[PATH_MAX];
    char *mod_path;
    unsigned int prev_size;
    unsigned int i;

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

    parsed_url_free(p_url);

    // call rsync to fetch the file locally
    pid = fork();

    if (pid == -1) { // unable to fork
        perror("Unable to fork");
    } else if (pid == 0) { // in the child
        close(STDERR_FILENO);
        close(STDIN_FILENO);
        if (execle("/usr/bin/rsync",
                   "rsync", "--archive", "-hh",
                   "--partial", "--modify-window=2",
                   "-e", ssh_info,
                   src, dest, (char *)0, NULL) == -1) { exit(EXIT_FAILURE); }
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

static def_fun_api(sock_open, int, *(sk_type_t *) ARGS[0], *(int *) ARGS[1], *(const struct sockaddr **) ARGS[2],
                   *(socklen_t *) ARGS[3])

int sock_open(UNUSED context_t *ctx, sk_type_t proto, int af, const struct sockaddr *addr, socklen_t len) {
    return ctx_open(proto, af, addr, len);
}

static def_fun_api(sock_write, int, *(int *) ARGS[0], *(const void **) ARGS[1], *(uint64_t *) ARGS[2])

int sock_write(UNUSED context_t *ctx, int sfd, const void *buf, uint64_t len) {
    return ctx_write(sfd, buf, len);
}

static def_fun_api(sock_read, int, *(int *) ARGS[0], *(void **) ARGS[1], *(uint64_t *) ARGS[2])

int sock_read(UNUSED context_t *ctx, int sfd, void *buf, uint64_t len) {
    return ctx_read(sfd, buf, len);
}

static def_fun_api(sock_close, int, *(int *) ARGS[0])

int sock_close(UNUSED context_t *ctx, int sfd) {
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

/*
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
 */

static def_fun_api(reschedule_plugin, int, *(time_t **) ARGS[0])

int reschedule_plugin(context_t *ctx, time_t *time) {
    if (!is_job_plugin(ctx->p)) {
        return -1;
    }

    return reschedule_job(ctx->p, time);
}

static def_fun_api(whereami, int)

int whereami(context_t *ctx) {
    return ctx->pop->point->id;
}


proto_ext_fun_t base_api_fun__[] = {
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint16},
                .return_type= &ffi_type_uint16,
                .fn= super_ntohs,
                .args_nb= 1,
                .name="ebpf_ntohs",
                .attributes=HELPER_ATTR_NONE,
                .closure_fn=api_name_closure(super_ntohs),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint32},
                .return_type = &ffi_type_uint32,
                .fn = super_ntohl,
                .args_nb = 1,
                .name = "ebpf_ntohl",
                .attributes= HELPER_ATTR_NONE,
                .closure_fn=api_name_closure(super_ntohl),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint64},
                .return_type = &ffi_type_uint64,
                .fn = super_ntohll,
                .args_nb = 1,
                .name = "ebpf_ntohll",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(super_ntohll)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint16},
                .return_type= &ffi_type_uint16,
                .fn= super_htons,
                .args_nb= 1,
                .name="ebpf_htons",
                .attributes=HELPER_ATTR_NONE,
                .closure_fn=api_name_closure(super_htons),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint32},
                .return_type = &ffi_type_uint32,
                .fn = super_ntohl,
                .args_nb = 1,
                .name = "ebpf_htonl",
                .attributes= HELPER_ATTR_NONE,
                .closure_fn=api_name_closure(super_htonl),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint64},
                .return_type = &ffi_type_uint64,
                .fn = super_ntohll,
                .args_nb = 1,
                .name = "ebpf_htonll",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(super_htonll)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer, &ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .fn = super_log,
                .args_nb = 2,
                .name = "super_log",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(super_log)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint64},
                .return_type = &ffi_type_pointer,
                .fn = ctx_malloc,
                .args_nb = 1,
                .name = "ctx_malloc",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ctx_malloc),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint64, &ffi_type_uint64},
                .return_type = &ffi_type_pointer,
                .fn = ctx_calloc,
                .args_nb = 2,
                .name = "ctx_calloc",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ctx_calloc),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer, &ffi_type_uint64},
                .return_type = &ffi_type_pointer,
                .fn = ctx_realloc,
                .args_nb = 2,
                .name = "ctx_realloc",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ctx_realloc),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_void,
                .fn = ctx_free,
                .args_nb = 1,
                .name = "ctx_free",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ctx_free),
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint, &ffi_type_uint64},
                .return_type = &ffi_type_pointer,
                .fn = ctx_shmnew,
                .args_nb = 2,
                .name = "ctx_shmnew",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn= api_name_closure(ctx_shmnew)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint},
                .return_type = &ffi_type_pointer,
                .fn = ctx_shmget,
                .args_nb = 1,
                .name = "ctx_shmget",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn= api_name_closure(ctx_shmget)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint},
                .return_type = &ffi_type_void,
                .fn = ctx_shmrm,
                .args_nb = 1,
                .name = "ctx_shmrm",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn= api_name_closure(ctx_shmrm)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type =  &ffi_type_sint,
                .fn = get_time,
                .args_nb = 1,
                .name =  "get_time",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_time)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type =  &ffi_type_sint,
                .fn = get_realtime,
                .args_nb = 1,
                .name =  "get_realtime",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_realtime)
        },
        {
                .args_type =  (ffi_type *[]) {&ffi_type_pointer, &ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .fn =  ebpf_print_intern,
                .args_nb = 2,
                .name = "ebpf_print_intern",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ebpf_print_intern)
        },
        {
                .args_type = NULL,
                .return_type = &ffi_type_sint,
                .fn = next,
                .args_nb = 0,
                .name = "next",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(next)
        },
        {
                .args_type =  (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                },
                .return_type = &ffi_type_sint,
                .fn = ebpf_bvsnprintf,
                .args_nb = 4,
                .name = "ebpf_bvsnprintf",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ebpf_bvsnprintf)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                        &ffi_type_uint64,
                },
                .return_type = &ffi_type_pointer,
                .fn = ebpf_memcpy,
                .args_nb = 3,
                .name = "ebpf_memcpy",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ebpf_memcpy)
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint,},
                .return_type = &ffi_type_pointer,
                .fn = get_arg,
                .args_nb = 1,
                .name = "get_arg",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_arg)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_uint64,
                        &ffi_type_uint64,
                        &ffi_type_uint64
                },
                .return_type = &ffi_type_void,
                .fn = membound_fail,
                .args_nb = 3,
                .name = "membound_fail",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(membound_fail)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_uint64,
                        &ffi_type_uint
                },
                .return_type = &ffi_type_uint64,
                .fn = ebpf_sqrt,
                .args_nb = 2,
                .name = "ebpf_sqrt",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ebpf_sqrt)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                        &ffi_type_uint64,
                },
                .return_type = &ffi_type_sint,
                .fn = ebpf_memcmp,
                .args_nb = 3,
                .name = "ebpf_memcmp",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(ebpf_memcmp)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                        &ffi_type_uint64,
                },
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn = get_extra_info_value,
                .name = "get_extra_info_value",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_extra_info_value)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_sint,
                        &ffi_type_pointer
                },
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn = get_extra_info_lst_idx,
                .name = "get_extra_info_lst_idx",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_extra_info_lst_idx)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                },
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn =      get_extra_info_dict,
                .name = "get_extra_info_dict",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_extra_info_dict)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer
                },
                .return_type = &ffi_type_sint,
                .args_nb = 2,
                .fn = get_extra_info,
                .name = "get_extra_info",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_extra_info)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_uint64
                },
                .return_type = &ffi_type_sint,
                .args_nb = 4,
                .fn = ebpf_inet_ntop,
                .name = "ebpf_inet_ntop",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn =api_name_closure(ebpf_inet_ntop)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_pointer,
                        &ffi_type_uint64
                },
                .return_type = &ffi_type_sint,
                .args_nb = 4,
                .fn = ebpf_inet_pton,
                .name = "ebpf_inet_pton",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn =api_name_closure(ebpf_inet_pton)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                        &ffi_type_pointer
                },
                .return_type = &ffi_type_sint,
                .args_nb = 2,
                .fn = fetch_file,
                .name = "fetch_file",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(fetch_file)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint, // enums are as large as int
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_uint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 4,
                .fn = sock_open,
                .name = "sock_open",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(sock_open)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_uint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn = sock_write,
                .name = "sock_write",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(sock_write)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint,
                        &ffi_type_pointer,
                        &ffi_type_uint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn = sock_read,
                .name = "sock_read",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(sock_read)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint,
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = sock_close,
                .name = "sock_close",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(sock_close)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_pointer,
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = reschedule_plugin,
                .name = "reschedule_plugin",
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(reschedule_plugin)
        },
        {
            .args_type = NULL,
            .return_type = &ffi_type_sint,
            .args_nb = 0,
            .fn = whereami,
            .name = "whereami",
            .attributes = HELPER_ATTR_NONE,
            .closure_fn = api_name_closure(whereami)
        }
};

const int base_api_fun_len__ = sizeof(base_api_fun__) / sizeof(base_api_fun__[0]);