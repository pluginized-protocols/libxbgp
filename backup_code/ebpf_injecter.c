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
#include <fcntl.h>
#include <sys/mman.h>
#include <json-c/json.h>

static int msqid = -1;
static int shared_fd = -1;

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


int send_pluglet_transaction(const char *name_plugin, const char *path, size_t extra_mem, size_t shared_mem,
                             int plugin_id, int pluglet_type, uint32_t seq, uint8_t jit) {

    if (msqid == -1 || shared_fd == -1) {
        fprintf(stderr, "Can't send plugin to the remote program (msqid, shmem_fd not INIT)\n");
        return -1;
    }

    send_pluglet(path, name_plugin, jit, pluglet_type, E_BPF_TRANSACTION_ADD,
                 extra_mem, shared_mem, seq, msqid, shared_fd);

    return 0;
}

int send_transaction(const char *path) {

    if (send_begin_transaction(msqid) != 0) return -1;
    if (load_plugin_from_json_fn(path, NULL, 0, send_pluglet_transaction) != 0) return -1;
    if (send_finish_transaction(msqid) != 0) return -1;

    return 0;
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
    char shared_mem_str[NAME_MAX];
    char path_json[PATH_MAX];
    char *ptr_path = NULL;
    char *err;
    unsigned int plugin_action = -1;

    long _msqid;
    int is_transaction = 0;
    ubpf_queue_info_msg_t msg;


    memset(path, 0, sizeof(char) * PATH_MAX);
    memset(plug_name, 0, sizeof(char) * NAME_MAX);

    while ((opt = getopt(argc, argv, "h:p:a:e:s:n:ji:m:s:")) != -1) {

        switch (opt) {
            case 't': { /* transaction path to the JSON instruction file*/

                memset(path_json, 0, PATH_MAX * sizeof(char));
                strncpy(path_json, optarg, PATH_MAX);

                if (access(path_json, R_OK) != 0) {
                    perror("Can't read JSON path");
                    return EXIT_FAILURE;
                }
                is_transaction += 1;
            }
            case 'm': /* message queue ID to send message to the protocol */

                _msqid = strtol(optarg, &err, 10);

                if (*err != '\0') {
                    perror("Can't parse message queue");
                    failed_args++;
                } else if (_msqid >= UINT32_MAX) {
                    fprintf(stderr, "Found msqid > 2**32. Expected msqid < 2**32\n");
                    failed_args++;
                }

                msqid = (int) _msqid;

                break;
            case 's': { /* name shared memory region */

                size_t total = 0;

                int fd = open(optarg, O_RDONLY);
                int s, finished = 0;
                if (fd == -1) {
                    perror("Can't open file");
                    failed_args++;
                }

                while (total < PATH_MAX && !finished) {

                    s = read(fd, shared_mem_str + total, PATH_MAX - total);
                    if (s == -1) {
                        perror("Error while reading file");
                        failed_args++;
                        finished = 1;
                    } else total += s;

                }

                shared_fd = shm_open(shared_mem_str, O_RDWR, S_IRUSR | S_IWUSR);
                if (shared_fd < 0) {
                    perror("Can't open shared memory");
                    failed_args++;
                }
                break;
            }
            case 'i': /* plugin name */
                strncpy(plug_name, optarg, NAME_MAX);
                break;
            case 'h': /* hook type */
                hook = strncmp("pre", optarg, 3) == 0 ? BPF_PRE :
                       strncmp("replace", optarg, 7) == 0 ? BPF_REPLACE :
                       strncmp("post", optarg, 4) == 0 ? BPF_POST : -1;

                if (hook == -1) {
                    fprintf(stderr, "Unrecognized anchor %s\n", optarg);
                    failed_args++;
                }
                break;
            case 'e': /* if new pluglet, specify the size of the extra memory */
                extra_mem = strtoll(optarg, &err, 10);
                if (*err != 0) {
                    failed_args++;
                    perror("Parsing -e number failed");
                }
                break;
            case 'n': /* sequence number for pre or post anchor */
                sequence_number = strtoll(optarg, &err, 10);
                if (*err != 0) {
                    failed_args++;
                    perror("Parsing -n number failed");
                }
                break;
            case 'j': /* enable jit compilation */
                jit = 1;
                break;
            case 'p': /* path to the eBPF ELF bytecode */
                if (!realpath(optarg, path)) {
                    failed_args++;
                    perror("Unable to resolve the path (-p argument)");
                } else {
                    ptr_path = path;
                }
                break;
            case 'a': /* action for this pluglet */
                plugin_action = strncmp(optarg, "add", 3) == 0 ? E_BPF_ADD :
                                strncmp(optarg, "rm", 2) == 0 ? E_BPF_RM :
                                strncmp(optarg, "replace", 7) == 0 ? E_BPF_REPLACE :
                                strncmp(optarg, "rm_pluglet", 10) == 0 ? E_BPF_RM_PLUGLET :
                                strncmp(optarg, "transaction", 10) == 0 ? E_BPF_TRANSACTION :
                                strncmp(optarg, "monitoring", 10) == 0 ? E_BPF_CHANGE_MONITORING : -1;

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

    if (msqid == -1) return -1;


    // SEND FULL eBPF PROGRAM TO THE PROTOCOL
    switch (plugin_action) { // check if every argument are there
        case E_BPF_REPLACE:
        case E_BPF_ADD:
            if (*path == 0) return EXIT_FAILURE;
            if (hook == -1) return EXIT_FAILURE;

            if (hook == BPF_POST || hook == BPF_PRE)
                if (sequence_number == -1) return EXIT_FAILURE;

            if (send_pluglet(ptr_path, plug_name, jit, hook, plugin_action,
                             extra_mem, shared_mem, sequence_number, msqid, shared_fd) != 0) {
                fprintf(stderr, "Unable to send plugin to protocol\n");
                return EXIT_FAILURE;
            }

        case E_BPF_RM:
            send_rm_plugin(msqid, plug_name);
            break;
        case E_BPF_RM_PLUGLET:
            send_rm_pluglet(msqid, plug_name, sequence_number, hook);
            break;
        case E_BPF_CHANGE_MONITORING:
            fprintf(stderr, "Monitoring change not implemented yet !\n");
            break;
        case E_BPF_TRANSACTION:
            if (is_transaction > 0) {
                if (is_transaction > 1) {
                    fprintf(stderr, "We only support one transaction file for now\n");
                    return EXIT_FAILURE;
                }

                if (send_transaction(path_json) != 0) return EXIT_FAILURE;
                return EXIT_SUCCESS;
            }

        default:
            return EXIT_FAILURE;
    }

    if (msgrcv(msqid, &msg, sizeof(ubpf_queue_info_msg_t), MTYPE_INFO_MSG, 0) == -1) {
        perror("Error while waiting protocol response");
        return EXIT_FAILURE;
    }

    return msg.status != STATUS_MSG_OK ?
           printf("KO...\n") && EXIT_FAILURE : printf("OK!\n") && EXIT_SUCCESS;
}