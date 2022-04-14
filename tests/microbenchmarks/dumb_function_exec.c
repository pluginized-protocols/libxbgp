//
// Created by thomas on 13/04/22.
//

#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "dumb_function_exec.h"

#include <ubpf_public.h>
#include "check_ret_vals.h"
#include "defs_type.h"

#include "plugins/dumb_functions.h"
#include "utils.h"
#include "dumb_function_exec.h"

#include <stdio.h>
#include <assert.h>

static struct {
    int id;
    const char *str_id;
    run_fn *fn;
} dumb_functions[] = {
        [dumb_fn_no_insts] = {.str_id = "dumb_fn_no_insts", .id = dumb_fn_no_insts, .fn = direct_return},
        [dumb_fn_loop_10] = {.str_id = "dumb_fn_loop_10", .id = dumb_fn_loop_10, .fn = loop_10},
        [dumb_fn_loop_100] = {.str_id = "dumb_fn_loop_100", .id = dumb_fn_loop_100, .fn = loop_100},
        [dumb_fn_loop_1000] = {.str_id = "dumb_fn_loop_1000", .id = dumb_fn_loop_1000, .fn = loop_1000},
        [dumb_fn_loop_10000] = {.str_id = "dumb_fn_loop_10000", .id = dumb_fn_loop_10000, .fn = loop_10000},
        [dumb_fn_loop_100000] = {.str_id = "dumb_fn_loop_100000", .id = dumb_fn_loop_100000, .fn = loop_100000},
        [dumb_fn_loop_1000000] = {.str_id = "dumb_fn_loop_1000000", .id = dumb_fn_loop_1000000, .fn = loop_1000000},
        [dumb_fn_loop_1000_1api] = {.str_id = "dumb_fn_loop_1000_1api", .id = dumb_fn_loop_1000_1api, .fn = loop_1000_1api},
        [dumb_fn_loop_1000_2api] = {.str_id = "dumb_fn_loop_1000_2api", .id = dumb_fn_loop_1000_1api, .fn = loop_1000_2api},
        [dumb_fn_loop_1000_3api] = {.str_id = "dumb_fn_loop_1000_3api", .id = dumb_fn_loop_1000_1api, .fn = loop_1000_3api},
};

int run_native_function(enum dumb_fn_id id, struct timespec *tp) {
    static int rand_init = 0;
    exec_info_t info;
    struct timespec total_time;

    if (id <= dumb_fn_id_min) {
        fprintf(stderr, "ID too small\n");
        return -1;
    }
    if (id >= dumb_fn_id_max) {
        fprintf(stderr, "ID to high\n");
        return -1;
    }
    if (!tp) return -1;

    if (!rand_init) {
        srand(time(NULL));
    }

    info = (exec_info_t) {
            .insertion_point_id =(int) rand(),
            .return_val_set = rand() % 2,
            .replace_return_value = rand()
    };

    if (measure_time(&total_time, dumb_functions[id].fn(&info);) != 0) {
        return -1;
    }

    *tp = total_time;
    return 0;
}

int run_plugin_function(enum dumb_fn_id id, struct timespec *tp) {
    int arg1 = 2;
    int ret;
    struct timespec total_time;
    int err;

    if (!tp) return -1;

    err = measure_time(&total_time,

                       entry_arg_t attr_args[] = {
                               {.arg = &arg1, .len = sizeof(arg1), .kind = kind_hidden, .type =  TYPE_INT},
                               {.arg = &id, .len = sizeof(id), .kind = kind_hidden, .type =TYPE_INT},
                               entry_arg_null
                       };

                               CALL_REPLACE_ONLY(id, attr_args, check_fake_call_vm, {
                                       ret = -2;
                               }, {
                                                         ret = 0;
                                                 });
    );

    if (err != 0) {
        return -1;
    }
    if (ret != 0) {
        return -1;
    }

    *tp = total_time;
    return 0;
}


static int run_function(struct run_config *run_config, FILE *save_result, enum dumb_fn_id id) {
    int i;
    size_t j;
    int line_len;
    size_t tot_written;
    struct timespec total_time;
    char buf_str[4096];

    static struct {
        int (*fn)(enum dumb_fn_id, struct timespec *);
        const char *str_type;
        int type_id;
    } funs[] = {
            {.fn = run_native_function, .str_type = "native", .type_id = NATIVE},
            {.fn = run_plugin_function, .str_type = "plugin", .type_id = PLUGIN},
    };

    static size_t funs_size = sizeof(funs) / sizeof(funs[0]);

    for (j = 0; j < funs_size; j++) {
        /* launch the mode only if it is authorized in the run_config */
        if (!(funs[j].type_id & run_config->exec_mode)) {
            continue;
        }

        for (i = 0; i < run_config->nb_run; i++) {
            if (funs[j].fn(id, &total_time) != 0) {
                return -1;
            }

            line_len = snprintf(buf_str, sizeof(buf_str), "%s_%s,%ld,%ld\n",
                                funs[j].str_type, dumb_functions[id].str_id, total_time.tv_sec, total_time.tv_nsec);

            if (line_len == sizeof(buf_str)) {
                fprintf(stderr, "Output may be truncated !\n");
            }

            tot_written = fwrite(buf_str, 1, line_len, save_result);
            assert(tot_written == line_len);
        }
    }

    return 0;
}


int run_functions(struct run_config *run_config) {
    int ret = -1;
    enum dumb_fn_id curr_fn;
    static const char csv_hdr[] = "fn_name,secs,nanosecs\n";
    size_t nb_written;

    FILE *csv_results = NULL;
    if (run_config->out_file) {
        csv_results = fopen(run_config->out_file, "w");
    } else {
        csv_results = stdout;
    }


    if (!csv_results) {
        perror("fopen csv_results");
        goto err;
    }

    nb_written = fwrite(csv_hdr, 1, sizeof(csv_hdr) - 1, csv_results);
    assert(nb_written == sizeof(csv_hdr) - 1);

    if (run_config->fn_to_run == dumb_fn_id_max) {
        for (curr_fn = dumb_fn_no_insts; curr_fn < dumb_fn_id_max; curr_fn++) {
            if (run_function(run_config, csv_results, curr_fn) != 0) {
                goto err;
            }
        }
    } else {
        if (run_function(run_config, csv_results, run_config->fn_to_run) != 0) {
            goto err;
        }
    }

    // everything went well
    ret = 0;

    err:
    if (csv_results != NULL && csv_results != stdout) {
        fclose(csv_results);
    }

    return ret;
}