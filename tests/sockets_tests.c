//
// Created by thomas on 15/02/21.
//
#include "sockets_tests.h"

#include <ubpf_public.h>
#include <plugins_manager.h>
#include <CUnit/CUnit.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include "utils_tests.h"

static const char *bytecode_dir = NULL;

static insertion_point_info_t plugins[] = {
        {.insertion_point_str = "tcp_socket_test", .insertion_point_id = 1},
        insertion_point_info_null
};

static proto_ext_fun_t funcs[] = { proto_ext_func_null };

static pid_t tcp_server = -1;


static int setup(void) {
    char final_path[PATH_MAX];
    struct timespec tp = {.tv_sec = 1, .tv_nsec = 0};

    tcp_server = fork();
    if (tcp_server == -1) {
        perror("fork");
        return -1;
    } else if (tcp_server == 0) {
        static const char *program_name = "exporter_example.py";
        memset(final_path, 0, sizeof(final_path));
        snprintf(final_path, sizeof(final_path), "%s/exporter_example.py", bytecode_dir);

        devnull_all_stdstream();
        if (execle(final_path, program_name, (char *) NULL, NULL) == -1) {
            msg_log(L_ERR "Execve failed %s\n", strerror(errno));
            exit(1);
        }
    }

    // We let the tcp_server starting before
    // testing if it is really up.
    if (nanosleep(&tp, NULL) == -1) {
        perror("nanosleep");
        return -1;
    }

    if (waitpid(tcp_server, NULL, WNOHANG) == -1) {
        perror("Error with tcp_server");
        return -1;
    }
    return init_plugin_manager(funcs, ".", plugins, 0, NULL);
}

static int teardown(void) {

    if (tcp_server != -1) {
        kill(tcp_server, SIGKILL);
    }

    // wait that the server is effectively killed
    waitpid(tcp_server, 0, 0);

    ubpf_terminate();
    return 0;
}


static void tcp_communication_plugin(void) {
    int status;
    char path_pluglet[PATH_MAX];
    insertion_point_t *pt;
    entry_arg_t *args;
    args_t fargs;
    uint64_t ret_val;

    int val = 22;

    memset(path_pluglet, 0, sizeof(path_pluglet));
    snprintf(path_pluglet, sizeof(path_pluglet), "%s/simple_tcp_connection.o", bytecode_dir);

    status = add_extension_code("example_tcp", 11, 128,
                                0, 1, "tcp_socket_test",
                                15, BPF_REPLACE, 0, 0,
                                path_pluglet, 0, "super_vm", 8, funcs, 0, 1, BUMP_MEM, 0);

    CU_ASSERT_EQUAL_FATAL(status, 0);
    pt = insertion_point(1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pt);


    args = (entry_arg_t[]) {
            {.arg = &val, .len = sizeof(val), .kind = kind_primitive, .type = 1},
            entry_arg_null,
    };

    fargs.args = args;
    fargs.nargs = 1;

    run_replace_function(pt, &fargs, &ret_val);


    // check if the plugin return the value sent by the TCP server
    CU_ASSERT_EQUAL(ret_val, 42);

    remove_plugin("example_tcp");
}


CU_ErrorCode test_socket_api(const char *plugin_folder) {
    CU_pSuite pSuite = NULL;

    if (plugin_folder == NULL) {
        return CUE_SINIT_FAILED;
    }
    bytecode_dir = plugin_folder;

    pSuite = CU_add_suite("plugin_socket_api", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Fetch data from tcp server", tcp_communication_plugin))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}