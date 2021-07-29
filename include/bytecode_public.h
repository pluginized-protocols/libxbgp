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


#define UTILITY_PP_CONCAT_(v1, v2) v1 ## v2
#define UTILITY_PP_CONCAT(v1, v2) UTILITY_PP_CONCAT_(v1, v2)

#define UTILITY_PP_CONCAT5_(_0, _1, _2, _3, _4) _0 ## _1 ## _2 ## _3 ## _4

#define UTILITY_PP_IDENTITY_(x) x
#define UTILITY_PP_IDENTITY(x) UTILITY_PP_IDENTITY_(x)

#define UTILITY_PP_VA_ARGS_(...) __VA_ARGS__
#define UTILITY_PP_VA_ARGS(...) UTILITY_PP_VA_ARGS_(__VA_ARGS__)

#define UTILITY_PP_IDENTITY_VA_ARGS_(x, ...) x, __VA_ARGS__
#define UTILITY_PP_IDENTITY_VA_ARGS(x, ...) UTILITY_PP_IDENTITY_VA_ARGS_(x, __VA_ARGS__)

#define UTILITY_PP_IIF_0(x, ...) __VA_ARGS__
#define UTILITY_PP_IIF_1(x, ...) x
#define UTILITY_PP_IIF(c) UTILITY_PP_CONCAT_(UTILITY_PP_IIF_, c)

#define UTILITY_PP_HAS_COMMA(...) UTILITY_PP_IDENTITY(UTILITY_PP_VA_ARGS_TAIL(__VA_ARGS__, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0))
#define UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_(...) ,

#define UTILITY_PP_IS_EMPTY(...) UTILITY_PP_IS_EMPTY_( \
    /* test if there is just one argument, eventually an empty one */ \
    UTILITY_PP_HAS_COMMA(__VA_ARGS__),                                \
    /* test if _TRIGGER_PARENTHESIS_ together with the argument adds a comma */ \
    UTILITY_PP_HAS_COMMA(UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_ __VA_ARGS__), \
    /* test if the argument together with a parenthesis adds a comma */ \
    UTILITY_PP_HAS_COMMA(__VA_ARGS__ ()),                             \
    /* test if placing it between _TRIGGER_PARENTHESIS_ and the parenthesis adds a comma */ \
    UTILITY_PP_HAS_COMMA(UTILITY_PP_IS_EMPTY_TRIGGER_PARENTHESIS_ __VA_ARGS__ ()))

#define UTILITY_PP_IS_EMPTY_(_0, _1, _2, _3) UTILITY_PP_HAS_COMMA(UTILITY_PP_CONCAT5_(UTILITY_PP_IS_EMPTY_IS_EMPTY_CASE_, _0, _1, _2, _3))
#define UTILITY_PP_IS_EMPTY_IS_EMPTY_CASE_0001 ,

#define UTILITY_PP_VA_ARGS_SIZE(...) UTILITY_PP_IIF(UTILITY_PP_IS_EMPTY(__VA_ARGS__))(0, UTILITY_PP_VA_ARGS_SIZE_(__VA_ARGS__, UTILITY_PP_VA_ARGS_SEQ64()))
#define UTILITY_PP_VA_ARGS_SIZE_(...) UTILITY_PP_IDENTITY(UTILITY_PP_VA_ARGS_TAIL(__VA_ARGS__))

#define UTILITY_PP_VA_ARGS_TAIL(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, x, ...) x
#define UTILITY_PP_VA_ARGS_SEQ64() 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0


#define NUMARGS_SPRINTF__(...)  (UTILITY_PP_VA_ARGS_SIZE(__VA_ARGS__))

#define ubpf_sprintf(str, size, format, ...)\
ebpf_bvsnprintf(str, size, format, (uintptr_t[]){NUMARGS_SPRINTF__(__VA_ARGS__), __VA_ARGS__})


#define NUMARGS_LOGMSG(...) (UTILITY_PP_VA_ARGS_SIZE(__VA_ARGS__))

#define LOG_S8(i) ((struct vtype) {.val = {.s8 = (i)}, .type = VT_S8})
#define LOG_U8(i) ((struct vtype) {.val = {.u8 = (i)}, .type = VT_U8})
#define LOG_S16(i) ((struct vtype) {.val = {.s16 = (i)}, .type = VT_S16})
#define LOG_U16(i) ((struct vtype) {.val = {.u16 = (i)}, .type = VT_U16})
#define LOG_S32(i) ((struct vtype) {.val = {.s32 = (i)}, .type = VT_S32})
#define LOG_U32(i) ((struct vtype) {.val = {.u32 = (i)}, .type = VT_U32})
#define LOG_S64(i) ((struct vtype) {.val = {.s64 = (i)}, .type = VT_S64})
#define LOG_U64(i) ((struct vtype) {.val = {.u64 = (i)}, .type = VT_U64})
#define LOG_FLOAT(i) ((struct vtype) {.val = {.fvalue = (i)}, .type = VT_FLOAT})
#define LOG_DOUBLE(i) ((struct vtype) {.val = {.dvalue = (i)}, .type = VT_DOUBLE})
#define LOG_LDOUBLE(i) ((struct vtype) {.val = {.ldvalue = (i)}, .type = VT_LONGDOUBLE})
#define LOG_PTR(i) ((struct vtype) {.val = {.pvalue = (void *)(i)}, .type = VT_POINTER})
#define LOG_STR(i) LOG_PTR(i)
#define LOG_SCHAR(i) ((struct vtype) {.val = {.schar = (i)}, .type = VT_SCHAR})
#define LOG_UCHAR(i) ((struct vtype) {.val = {.uchar = (i)}, .type = VT_UCHAR})
#define LOG_SSHORT(i) ((struct vtype) {.val = {.sshort = (i)}, .type = VT_SSHORT})
#define LOG_USHORT(i) ((struct vtype) {.val = {.ushort = (i)}, .type = VT_USHORT})
#define LOG_INT(i) ((struct vtype) {.val = {.sint = (i)}, .type = VT_SINT})
#define LOG_UINT(i) ((struct vtype) {.val = {.uint = (i)}, .type = VT_UINT})
#define LOG_SLONG(i) ((struct vtype) {.val = {.slong = (i)}, .type = VT_SLONG})
#define LOG_ULONG(i) ((struct vtype) {.val = {.ulong = (i)}, .type = VT_ULONG})
#define LOG_SLLONG(i) ((struct vtype) {.val = {.sllong = (i)}, .type = VT_SLLONG})
#define LOG_ULLONG(i) ((struct vtype) {.val = {.ullong = (i)}, .type = VT_ULLONG})

#define log_msg(format, ...) ({                       \
      struct vargs __vargs__ = {                      \
          .nb_args = NUMARGS_LOGMSG(__VA_ARGS__),     \
          .args = (struct vtype[]) {                  \
              __VA_ARGS__                             \
          }                                           \
      };                                              \
      super_log(format, &__vargs__);                  \
})


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

int ebpf_inet_pton(int af, const char *src, void *dst, size_t buf_len);

extern int super_log(const char *msg, struct vargs *args);

extern int sk_open(sk_type_t proto, int af, const struct sockaddr *addr, socklen_t len);

extern int sk_write(int sfd, const void *buf, size_t len);

extern int sk_read(int sfd, void *buf, size_t len);

extern int sk_close(int sfd);

extern int reschedule_plugin(time_t *time);

#endif //FRR_UBPF_PUBLIC_BPF_H
