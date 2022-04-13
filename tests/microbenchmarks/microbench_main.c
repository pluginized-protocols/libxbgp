//
// Created by thomas on 12/04/22.
//


#include <ubpf_public.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "defs_type.h"
#include "tests/microbenchmarks/plugins/dumb_functions.h"
#include "dumb_function_exec.h"
#include <unistd.h>
#include "utils.h"

static proto_ext_fun_t ext_funcs[] = {
        proto_ext_func_null
};

static insertion_point_info_t mock_insertion_points[] = {
        {.insertion_point_str="dumb_fn_no_insts", .insertion_point_id = dumb_fn_no_insts},
        {.insertion_point_str="dumb_fn_loop_10", .insertion_point_id = dumb_fn_loop_10},
        {.insertion_point_str="dumb_fn_loop_100", .insertion_point_id = dumb_fn_loop_100},
        {.insertion_point_str="dumb_fn_loop_1000", .insertion_point_id = dumb_fn_loop_1000},
        {.insertion_point_str="dumb_fn_loop_10000", .insertion_point_id = dumb_fn_loop_10000},
        {.insertion_point_str="dumb_fn_loop_100000", .insertion_point_id = dumb_fn_loop_100000},
        {.insertion_point_str="dumb_fn_loop_1000000", .insertion_point_id = dumb_fn_loop_1000000},
        insertion_point_info_null
};


static inline int setup(void) {
    if (init_plugin_manager(ext_funcs, "/tmp",
                            mock_insertion_points, 0, NULL)) {
        return -1;
    }

    return 0;
}

static inline void teardown(void) {
    ubpf_terminate();
}

static inline enum dumb_fn_id str_insertion_point_to_id(const char *i_point) {
    int i;
    const char *insertion_point_name;
    for (i = 0; !is_insertion_point_info_null(&mock_insertion_points[i]); i++) {
        insertion_point_name = mock_insertion_points[i].insertion_point_str;

        // 20 is max character for insertion point
        if (strncmp(insertion_point_name, i_point, 20) == 0) {
            return mock_insertion_points[i].insertion_point_id;
        }
    }
    return dumb_fn_id_min;
}

static inline int should_run_all(const char *str_fun) {
    static char all[] = "all";

    if (strnlen(str_fun, 5) != sizeof(all) - 1) {
        return 0;
    }

    return strncmp(str_fun, all, sizeof(all) - 1) == 0;
}


int main(int argc, char *const argv[]) {
    int ret;
    int c;
    int option_index = 0;
    const char *manifest_path = NULL;
    const char *plugin_dir = NULL;
    long nb_run_tmp;
    char *nb_ptr;
    enum dumb_fn_id tmp_fn_to_run;
    struct run_config run_config = {
            .out_file = NULL,
            .fn_to_run = dumb_fn_id_max,
            .nb_run = 50
    };

    if (setup() != 0) {
        fprintf(stderr, "Unable to init libxbgp\n");
        return EXIT_FAILURE;
    }

    static struct option long_options[] = {
            {"manifest", required_argument, 0, 'm'},
            {"plugin_dir", required_argument, 0, 'p'},
            {"nb_run", required_argument, 0, 'n'},
            {"fn_run", required_argument, 0, 'f'},
            {"output", required_argument, 0, 'o'},
            {0, 0, 0, 0}
    };

    while (1) {
        c = getopt_long(argc, argv, "m:p:n:f:o:",
                        long_options, &option_index);

        if (c == EOF) {
            break;
        }

        switch (c) {
            case 'm':
                if (manifest_path != NULL) {
                    fprintf(stderr, "manifest option already set once !\n");
                    return EXIT_FAILURE;
                }
                manifest_path = optarg;
                break;
            case 'p':
                if (plugin_dir != NULL) {
                    fprintf(stderr, "plugin_dir option already set once !\n");
                    return EXIT_FAILURE;
                }
                plugin_dir = optarg;
                break;
            case 'n':
                nb_run_tmp = strtol(optarg, &nb_ptr, 10);
                if (*nb_ptr != '\0') {
                    fprintf(stderr, "%s: %s is not a valid number\n", strerror(errno), optarg);
                    return EXIT_FAILURE;
                }
                if (nb_run_tmp <= 0) {
                    fprintf(stderr, "nb_run must be strictly positive\n");
                    return EXIT_FAILURE;
                }
                run_config.nb_run = nb_run_tmp;
                break;
            case 'f':
                tmp_fn_to_run = str_insertion_point_to_id(optarg);
                if (tmp_fn_to_run == dumb_fn_id_min) {
                    if (should_run_all(optarg)) {
                        tmp_fn_to_run = dumb_fn_id_max;
                    } else  {
                        fprintf(stderr, "You request to run \"%s\" but I don't know this function.\n",
                                optarg);
                        return EXIT_FAILURE;
                    }
                }
                run_config.fn_to_run = tmp_fn_to_run;
                break;
            case  'o':
                run_config.out_file = optarg;
                break;
            default:
                fprintf(stderr, "Unknown option: %o\n", c);
                return EXIT_FAILURE;
        }
    }

    if (!manifest_path || !plugin_dir) {
        fprintf(stderr, "Manifest and plugin_dir must be set");
        return EXIT_FAILURE;
    }

    if (load_extension_code(manifest_path, plugin_dir,
                            ext_funcs, mock_insertion_points) != 0) {
        fprintf(stderr, "Unable to load plugins from manifest\n");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[INFO] Running program with the following config:\n"
                    "run_config {\n"
                    "   nb_run = %ld;\n"
                    "   out_file = %s;\n"
                    "   fn_to_run = %u;\n"
                    "}\n", run_config.nb_run,
                    run_config.out_file,
                    run_config.fn_to_run);

    if (run_functions(&run_config) != 0) {
        fprintf(stderr, "RUN FAILED\n");
        ret = EXIT_FAILURE;
    } else {
        ret = EXIT_SUCCESS;
    }

    teardown();
    return ret;
}