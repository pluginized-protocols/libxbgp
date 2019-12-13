//
// Created by thomas on 28/01/19.
//

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/msg.h>
#include <pwd.h>
#include "plugins_manager.h"
#include <string.h>
#include <linux/limits.h>
#include <getopt.h>
#include <stdlib.h>

static inline void change_id_process(const char *user) {
    struct passwd *pwd;
    pwd = getpwnam(user);

    if (pwd == NULL) {
        perror("Can't retrieve info frr user");
        exit(EXIT_FAILURE);
    }

    if (setuid(pwd->pw_uid) == -1) {
        perror("Can't change process uid");
        exit(EXIT_FAILURE);
    }

}


static inline int usage(const char *argv) {

    fprintf(stderr, "%s: eBPF plugin injecter for libubpf\n"
                    "USAGE: %s -t type -a action [-p path_to_eBPF_bytecode]\n"
                    "\tBoth -t and -a are required. Available arguments are :\n"
                    "\t-h hook : on which anchor the pluglet must be injected ([pre|replace|post])\n"
                    "\t-p path_to_eBPF_bytecode : the path to the eBPF bytecode\n"
                    "\t-a action : which action to do with the plugin ( [add|rm|replace] )\n"
                    "\t-e extra_mem: extension of the stack in bytes\n"
                    "\t-s shared_mem: size of the memory used to share data\n"
                    "\t-n sequence number: only valid for pre and post anchor, indicate "
                    "the execution order of this pluglet\n"
                    "\t-j: if set, tells to compile the eBPF bytecode to the CPU native machine language.\n"
                    "\t-i insertion_point_name: name of the plugin",
            argv,
            argv
    );

    return EXIT_FAILURE;
}

int main(int argc, char *const argv[]) {

    int opt;
    int failed_args = 0;
    long long int extra_mem = 0;
    long long int shared_mem = 0;
    long long int sequence_number = -1;
    short jit = 0;
    int hook = -1;

    char path[PATH_MAX];
    char plug_name[NAME_MAX];
    char *ptr_path = NULL;
    char *err;
    unsigned int plugin_action = -1;

    int msqid;
    ubpf_queue_info_msg_t msg;


    memset(path, 0, sizeof(char) * PATH_MAX);
    memset(plug_name, 0, sizeof(char) * NAME_MAX);

    while ((opt = getopt(argc, argv, "h:p:a:e:s:n:ji:")) != -1) {

        switch (opt) {
            case 'i':
                strncpy(plug_name, optarg, NAME_MAX);
                break;
            case 'h':
                hook = strncmp("pre", optarg, 3) == 0 ? BPF_PRE :
                       strncmp("replace", optarg, 7) == 0 ? BPF_REPLACE :
                       strncmp("post", optarg, 4) == 0 ? BPF_POST : -1;

                if (hook == -1) {
                    fprintf(stderr, "Unrecognized anchor %s\n", optarg);
                    failed_args++;
                }
                break;
            case 'e':
                extra_mem = strtoll(optarg, &err, 10);
                if (*err != 0) {
                    failed_args++;
                    perror("Parsing -e number failed");
                }
                break;
            case 's':
                shared_mem = strtoll(optarg, &err, 10);
                if (*err != 0) {
                    failed_args++;
                    perror("Parsing -s number failed");
                }
                break;
            case 'n':
                sequence_number = strtoll(optarg, &err, 10);
                if (*err != 0) {
                    failed_args++;
                    perror("Parsing -n number failed");
                }
                break;
            case 'j':
                jit = 1;
                break;
            case 'p':
                if (!realpath(optarg, path)) {
                    failed_args++;
                    perror("Unable to resolve the path (-p argument)");
                } else {
                    ptr_path = path;
                }
                break;
            case 'a':
                plugin_action = strncmp(optarg, "add", 3) == 0 ? E_BPF_ADD :
                                strncmp(optarg, "rm", 2) == 0 ? E_BPF_RM :
                                strncmp(optarg, "replace", 7) == 0 ? E_BPF_REPLACE :
                                strncmp(optarg, "rm_pluglet", 10) == 0 ? E_BPF_RM_PLUGLET : -1;

                if (plugin_action == -1) {
                    fprintf(stderr, "Unrecognised action : (-a argument)\n");
                    return EXIT_FAILURE;
                }
                break;
            default:
                fprintf(stderr, "Unrecognised option -%c\n", opt);
                return EXIT_FAILURE;
        }

    }

    if (plugin_action == -1 || *plug_name == 0) {
        return usage(argv[0]);
    }

    if (failed_args) {
        fprintf(stderr, "%d error(s) encountered", failed_args);
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
            if (*path == 0) return EXIT_FAILURE;
            if (hook == -1) return EXIT_FAILURE;

            if (hook == BPF_POST || hook == BPF_PRE)
                if (sequence_number == -1) return EXIT_FAILURE;

            if (send_pluglet(ptr_path, plug_name, jit, hook, plugin_action,
                             extra_mem, shared_mem, sequence_number, msqid) != 0) {
                fprintf(stderr, "Unable to send plugin to protocol\n");
                return EXIT_FAILURE;
            }

            if (msgrcv(msqid, &msg, sizeof(ubpf_queue_info_msg_t), MTYPE_INFO_MSG, 0) == -1) {
                perror("Error while waiting protocol response");
                return EXIT_FAILURE;
            }

            fprintf(stdout, "%s\n", msg.reason);

            return msg.status == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
        case E_BPF_RM:
            send_rm_plugin(msqid, plug_name);
            break;
        case E_BPF_RM_PLUGLET:
            send_rm_pluglet(msqid, plug_name, sequence_number, hook);
        default:
            return EXIT_FAILURE;
    }


}