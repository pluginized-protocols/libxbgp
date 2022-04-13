//
// Created by thomas on 13/04/22.
//

#ifndef LIBXBGP_VM_UTILS_H
#define LIBXBGP_VM_UTILS_H

#include <string.h>

struct run_config {
    long nb_run;
    const char *out_file;
    enum dumb_fn_id fn_to_run;
};

#define timespec_diff(a, b, result)                   \
  do {                                                \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;  \
    if ((result)->tv_nsec < 0) {                      \
      --(result)->tv_sec;                             \
      (result)->tv_nsec += 1000000000;                \
    }                                                 \
  } while (0)

#define measure_time(tp, ...) ({                           \
    int res__ = 0;                                         \
    int err__ = 0;                                         \
    struct timespec start__, end__;                        \
    memset((tp), 0, sizeof(*(tp)));                        \
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start__) != 0) {   \
        err__ = 1;                                         \
    }                                                      \
    if (!err__) {                                          \
        do {                                               \
            __VA_ARGS__                                    \
        } while(0);                                        \
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end__) != 0) { \
            err__ = 1;                                     \
        }   else {                                         \
            timespec_diff(&end__, &start__, tp);           \
        }                                                  \
    }                                                      \
    res__ = err__ ? -1 : 0;                                \
    res__;                                                 \
})

#endif //LIBXBGP_VM_UTILS_H
