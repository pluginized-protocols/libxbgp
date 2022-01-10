//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_PLUGIN_ARGUMENTS_H
#define FRR_UBPF_PLUGIN_ARGUMENTS_H

#include <stddef.h>
#include <stdint.h>

#define kind_null 0
#define kind_ptr 1
#define kind_primitive 2
#define kind_hidden 3

#define entry_arg_null {.arg = NULL, .len = 0, .kind = 0, .type = 0}
#define entry_is_null(entry) (((entry)->arg == NULL) && ((entry)->len == 0) && ((entry)->kind == 0) && ((entry)->type == 0))

#define build_args(entries) \
({ int i__;                               \
args_t args__;                            \
i__ = 0;                                  \
while(!entry_is_null(&(entries)[i__])) {  \
    i__++;                                \
}                                         \
args__.args = (entries);                  \
args__.nargs = i__;                     \
args__;})

typedef struct entry_arg_t {
    void *arg;
    size_t len;
    short kind;
    int type; // custom type defined by the protocol insertion point
} entry_arg_t;

typedef struct {
    entry_arg_t *args;
    int nargs;
} args_t;


/* used to pass variadic arguments (e.g. sprintf, log, printf) */
struct vtype {
    int type;
    union {
        int8_t s8;
        uint8_t u8;
        int16_t s16;
        uint16_t u16;
        int32_t s32;
        uint32_t u32;
        int64_t s64;
        uint64_t u64;
        float fvalue;
        double dvalue;
        long double ldvalue;
        void *pvalue;

        unsigned char uchar;
        char schar;
        unsigned short ushort;
        short sshort;
        unsigned int uint;
        int sint;
        unsigned long ulong;
        long slong;
        unsigned long long ullong;
        long long sllong;
    } val;
};

struct vargs {
    int nb_args;
    struct vtype *args;
};

enum {
    VT_S8, VT_U8,
    VT_S16, VT_U16,
    VT_S32, VT_U32,
    VT_S64, VT_U64,
    VT_FLOAT, VT_DOUBLE, VT_LONGDOUBLE,
    VT_POINTER,
    VT_UCHAR, VT_SCHAR,
    VT_USHORT, VT_SSHORT,
    VT_UINT, VT_SINT,
    VT_SLONG, VT_ULONG,
    VT_ULLONG, VT_SLLONG
};


#endif //FRR_UBPF_PLUGIN_ARGUMENTS_H
