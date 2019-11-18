//
// Created by thomas on 28/01/19.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/msg.h>
#include <pwd.h>
#include "plugins_manager.h"
#include "defaults.h"





static inline void change_id_process(){
    struct passwd *pwd;
    pwd = getpwnam(FRR_USER);

    if(pwd == NULL){
        perror("Can't retrieve info frr user");
        exit(EXIT_FAILURE);
    }

    if(setuid(pwd->pw_uid) == -1){
        perror("Can't change process uid");
        exit(EXIT_FAILURE);
    }

}


static inline int usage(const char *argv) {

    fprintf(stderr, "%s: eBPF plugin injecter to BGP protocol\n"
                    "USAGE: %s -t type -a action [-p path_to_eBPF_bytecode]\n"
                    "\tBoth -t and -a are required. Available arguments are :\n"
                    "\t-t type : the location where the plugin should be executed in BGP protocol\n"
                    "\t-p path_to_eBPF_bytecode : the path to the eBPF bytecode\n"
                    "\t-a action : which action to do with the plugin ( [add|rm|replace] )\n",
            argv,
            argv
    );

    return EXIT_FAILURE;
}

int main(int argc, char *const argv[]) {

    int opt;
    int t_arg = 0;
    int p_arg = 0;
    int a_arg = 0;
    int failed_args = 0;

    char path[PATH_MAX];
    char *ptr_path = NULL;
    char *err;
    long long int location = -1;
    unsigned int plugin_action = 0;
    long long int tmp;

    int msqid;
    ubpf_queue_info_msg_t msg;


    memset(path, 0, sizeof(char) * PATH_MAX);

    while ((opt = getopt(argc, argv, "t:p:a:")) != -1) {

        switch (opt) {
            case 't':
                t_arg = 1;

                tmp = strtoll(optarg, &err, 10);

                if (*err != '\0') {
                    failed_args++;
                    perror("Cannot read -t argument");
                    fprintf(stderr, "%s is not a valid base 10 number (unrecognized string %s)", optarg, err);
                } else if (tmp > UINT32_MAX - 1) {
                    failed_args++;
                    fprintf(stderr, "-t argument is too high (max 2^32 - 1)\n");
                } else if (tmp <= 0) {
                    failed_args++;
                    fprintf(stderr, "-t argument must be strictly greater than 0\n");
                } else {
                    location = tmp;
                }

                break;
            case 'p':
                p_arg = 1;
                if (!realpath(optarg, path)) {
                    failed_args++;
                    perror("Unable to resolve the path (-p argument)");
                } else {
                    ptr_path = path;
                }
                break;
            case 'a':
                a_arg = 1;
                if (strncmp(optarg, "add", 3) == 0) {
                    plugin_action = E_BPF_ADD;
                } else if (strncmp(optarg, "rm", 2) == 0) {
                    plugin_action = E_BPF_RM;
                } else if (strncmp(optarg, "replace", 7) == 0) {
                    plugin_action = E_BPF_REPLACE;
                } else {
                    fprintf(stderr, "Unrecognised action : (-a argument)\n");
                    return EXIT_FAILURE;
                }
                break;
            default:
                fprintf(stderr, "Unrecognised option -%c\n", opt);
                return EXIT_FAILURE;
        }

    }

    if (!t_arg || !a_arg) {
        return usage(argv[0]);
    }

    if (failed_args) {
        fprintf(stderr, "%i error(s) encountered", failed_args);
        return EXIT_FAILURE;
    }

    //change_id_process();

    msqid = init_upbf_inject_queue_snd();

    if (msqid == -1) {
        fprintf(stderr, "Check if protocol is running\n");
        return EXIT_FAILURE;
    }

    // SEND FULL eBPF PROGRAM TO BGP
    switch (plugin_action) { // check if every argument are there
        case E_BPF_REPLACE:
        case E_BPF_ADD:
            if (!p_arg) {
                fprintf(stderr, "You must specify a path when adding|replacing new plugins\n");
                return EXIT_FAILURE;
            }
            break;

        case E_BPF_RM:
            break;
        default:
            return EXIT_FAILURE;
    }

    if (send_plugin(ptr_path, ptr_path ? strlen(path) : 0, (unsigned int) location, plugin_action, msqid) != 0) {
        fprintf(stderr, "Unable to send plugin to protocol\n");
        return EXIT_FAILURE;
    }

    if (msgrcv(msqid, &msg, sizeof(ubpf_queue_info_msg_t), MTYPE_INFO_MSG, 0) == -1) {
        perror("Error while waiting protocol response");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "%s\n", msg.reason);

    return msg.status == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}