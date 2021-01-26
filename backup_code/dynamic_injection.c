//
// Created by thomas on 1/07/20.
//

#include "dynamic_injection.h"

typedef struct ubpf_queue_msg {

    long mtype;
    unsigned int plugin_action;
    short jit;
    char plugin_name[NAME_MAX + 1];
    size_t bytecode_length;
    int hook;
    uint32_t seq;
    uint16_t extra_memory;
    uint16_t shared_memory;

} ubpf_queue_msg_t;

typedef struct ubpf_queue_info_msg {

    long mtype;
    status_t status; // failed or not

} ubpf_queue_info_msg_t;

struct json_pluglet_args {
    const char *name;
    int32_t str_len;
    int jit;
};

int init_ubpf_inject_queue() {
    int msqid;
    int curr_errno;
    int r;
    key_t key;
    struct timespec ts;

    if (timespec_get(&ts, TIME_UTC) == 0) {
        perror("TimeSpec");
        return -1;
    }
    srandom(ts.tv_nsec ^ ts.tv_sec);  /* Seed the PRNG */

    do {
        r = (int) random();
        key = ftok(daemon_vty_dir, r);
        msqid = msgget(key, 0600u | IPC_CREAT | IPC_EXCL);
        curr_errno = errno;
        if (msqid < 0) {
            if (curr_errno != EEXIST) {
                perror("Unable to create the queue");
                return -1;
            }
        }
    } while (curr_errno == EEXIST && msqid < 0);

    msqid_listener = msqid;
    return msqid;
}

static inline int generate_random_string(char *buffer, size_t len_buffer) {

    struct timespec ts;
    size_t i;
    char curr_char;
    long super_random;

    if (timespec_get(&ts, TIME_UTC) == 0) return -1;
    srandom(ts.tv_nsec ^ ts.tv_sec);  /* Seed the PRNG */

    for (i = 0; i < len_buffer; i++) {

        super_random = random() % 63; // distribution to be weighted to the size of the intervals
        if (super_random <= 25) {
            curr_char = (char) ((random() % ('z' - 'a' + 1)) + 'a');
        } else if (super_random <= 52) {
            curr_char = (char) ((random() % ('Z' - 'A' + 1)) + 'A');
        } else {
            curr_char = (char) ((random() % ('9' - '0' + 1)) + '0');
        }

        buffer[i] = curr_char;
    }

    return 0;
}

int init_shared_memory(char *shared_mem_name) { // shared_mem_name MUST be of size NAME_MAX
    int oflag, fd;
    int must_cont;
    char *rnd_name;
    char name[NAME_MAX];
    mode_t mode;
    *name = '/';

    uint8_t *data_ptr;

    rnd_name = name + 1;
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP; // rw-rw----
    oflag = O_RDWR | O_CREAT | O_EXCL;

    do {
        memset(rnd_name, 0, NAME_MAX - 1);
        if (generate_random_string(rnd_name, NAME_MAX - 2) != 0) return -1;
        rnd_name[NAME_MAX - 2] = 0;
        fd = shm_open(name, oflag, mode);
        if (fd < 0) {
            if (errno == EEXIST) must_cont = 1;
            else return -1;
        } else must_cont = 0;
    } while (must_cont);

    data_ptr = mmap(NULL, MAX_SIZE_PLUGIN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data_ptr == (void *) -1) {
        perror("MMAP initialization failed");
        return -1;
    }

    mmap_shared_ptr = data_ptr;

    strncpy(shared_mem_name, name, NAME_MAX);
    return fd;
}

int close_shared_memory() {

    if (munmap(mmap_shared_ptr, MAX_SIZE_PLUGIN) != 0) {
        perror("Unable to detach shared memory");
    }

    return shm_unlink(shm_plugin_name);
}

static inline __off_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        perror("Can't retrieve stats for file");
        return -1;
    }
    return st.st_size;
}

int send_pluglet(const char *path, const char *plugin_name, short jit, int hook, unsigned int action,
                 uint16_t extra_mem, uint16_t shared_mem, uint32_t seq, int msqid, int shared_fd) {

    ubpf_queue_msg_t msg;
    __off_t size;
    size_t len;

    char rel_path[PATH_MAX];
    int plug_id;

    plug_id = str_plugin_to_int(plugin_name);
    if (plug_id == -1) return -1;

    if (path) {
        realpath(path, rel_path);

        if (access(rel_path, R_OK) == -1) {
            perror("Read attribute missing to the file");
            return -1; // Can't read ubpf file
        }
    } else if (action != E_BPF_ADD && action != E_BPF_REPLACE &&
               action != E_BPF_RM && action != E_BPF_TRANSACTION_ADD) { // check if action is not add or replace
        fprintf(stderr, "Bad action\n");
        return -1;
    }

    size = file_size(path);
    if (size == -1) return -1;

    if ((len = store_plugin((size_t) size, path, shared_fd)) == 0) {
        return -1;
    }

    assert(len == (size_t) size && "Read length vs actual size differ in size");

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = action;
    msg.jit = jit;
    msg.hook = hook;
    msg.seq = hook == BPF_REPLACE ? 0 : seq;
    msg.extra_memory = extra_mem;
    msg.shared_memory = shared_mem;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Plugin send error [msgsnd]");
        return -1;
    }

    return 0;
}


int send_rm_plugin(int msqid, const char *plugin_name) {

    ubpf_queue_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_RM;
    strncpy(msg.plugin_name, plugin_name, NAME_MAX);

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Plugin send error [msgsnd]");
        return -1;
    }

    return 0;
}

int send_rm_pluglet(int msqid, const char *plugin_name, uint32_t seq, int anchor) {

    ubpf_queue_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_RM_PLUGLET;
    strncpy(msg.plugin_name, plugin_name, NAME_MAX);
    msg.seq = seq;
    msg.hook = anchor;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Message send error [msgsnd]");
        return -1;
    }

    return 0;
}

int send_begin_transaction(int msqid) {
    ubpf_queue_msg_t msg;
    ubpf_queue_info_msg_t from_ebpf;
    memset(&msg, 0, sizeof(msg));

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_TRANSACTION_BEGIN;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Error while sending message");
        return -1;
    }

    if (msgrcv(msqid, &from_ebpf, sizeof(ubpf_queue_info_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
        perror("Unable to get a response from");
    }

    if (from_ebpf.status != STATUS_MSG_OK) return -1;

    return 0;
}

int send_finish_transaction(int msqid) {
    ubpf_queue_msg_t msg;
    ubpf_queue_info_msg_t from_ebpf;
    memset(&msg, 0, sizeof(msg));

    msg.mtype = MTYPE_EBPF_ACTION;
    msg.plugin_action = E_BPF_TRANSACTION_END;

    if (msgsnd(msqid, &msg, sizeof(ubpf_queue_msg_t), 0) == -1) {
        perror("Error while sending message");
        return -1;
    }

    if (msgrcv(msqid, &from_ebpf, sizeof(ubpf_queue_info_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
        perror("Unable to get a response from");
    }

    if (from_ebpf.status != STATUS_MSG_OK) return -1;
    return 0;
}


size_t store_plugin(size_t size, const char *path, int shared_fd) {

    uint8_t *data;
    size_t plugin_length;

    data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);

    if (data == (void *) -1) {
        perror("Can't attach shared memory");
    }

    memset(data, 0, size);

    if (!readfileOwnPtr(path, MAX_SIZE_PLUGIN, &plugin_length, data)) {
        fprintf(stderr, "Cannot read bytecode\n");
        return 0;
    }

    munmap(data, size);

    return plugin_length;
}

static void *plugin_msg_handler(void *args) {

    ubpf_queue_info_msg_t info;
    args_plugins_msg_hdlr_t *cast_args = args;

    int err = 0;
    int internal_err = 0;
    int plugin_id;
    int mysqid;

    int transaction_begin = 0;

    info.mtype = MTYPE_INFO_MSG;

    if (!args) {
        fprintf(stderr, "No kernel queue ID received, EXITING...\n");
        exit(EXIT_FAILURE);
    }

    mysqid = cast_args->msqid;
    // fd = cast_args->shm_fd;
    ubpf_queue_msg_t rcvd_msg;

    free(args);

    while (!finished) {
        err = internal_err = 0;
        memset(&rcvd_msg, 0, sizeof(ubpf_queue_msg_t));

        if (msgrcv(mysqid, &rcvd_msg, sizeof(ubpf_queue_msg_t), MTYPE_EBPF_ACTION, 0) == -1) {
            continue;
        }

        if (msync(mmap_shared_ptr, MAX_SIZE_PLUGIN, MS_SYNC) != 0) return NULL;

        switch (rcvd_msg.hook) {
            case BPF_PRE:
            case BPF_POST:
            case BPF_REPLACE:
                break;
            default:
                fprintf(stderr, "Unrecognized plugin anchor/hook\n");
                err = 1;
                goto end;
        }

        plugin_id = str_plugin_to_int(rcvd_msg.plugin_name);
        if (plugin_id == -1) continue;

        switch (rcvd_msg.plugin_action) {
            case E_BPF_REPLACE:
            case E_BPF_ADD:
                if (__add_pluglet_ptr(mmap_shared_ptr, plugin_id, rcvd_msg.hook, rcvd_msg.bytecode_length,
                                      rcvd_msg.extra_memory, rcvd_msg.shared_memory, rcvd_msg.seq,
                                      rcvd_msg.jit, &internal_err) < 0) {
                    err = 1;
                    info.status = internal_err;
                }
                break;
            case E_BPF_RM:
                if (rm_plugin(plugin_id, &internal_err) == -1) {
                    err = 1;
                    info.status = internal_err;
                }
                break;
            case E_BPF_RM_PLUGLET:
                if (rm_pluglet(plugin_id, rcvd_msg.seq, rcvd_msg.hook)) {
                    err = 1;
                    info.status = STATUS_MSG_PLUGLET_RM_FAIL;
                }
                break;
            case E_BPF_TRANSACTION_BEGIN:
                if (transaction_begin > 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_IN_PROGRESS;
                } else {
                    transaction_begin = 1;
                }
                break;
            case E_BPF_TRANSACTION_ADD:
                if (transaction_begin == 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_NOT_BEGIN;
                } else if (__add_pluglet_ptr(mmap_shared_ptr, plugin_id, rcvd_msg.hook, rcvd_msg.bytecode_length,
                                             rcvd_msg.extra_memory, rcvd_msg.shared_memory,
                                             rcvd_msg.seq, rcvd_msg.jit, &internal_err) < 0) {
                    err = 1;
                    info.status = internal_err;
                } else {
                    // OK !
                }
                break;
            case E_BPF_TRANSACTION_END:
                if (transaction_begin == 0) {
                    err = 1;
                    info.status = STATUS_MSG_NO_TRANSACTION;
                } else if (commit_transaction(plugins_manager->ubpf_machines[plugin_id]) != 0) {
                    err = 1;
                    info.status = STATUS_MSG_TRANSACTION_FAIL;
                }
                transaction_begin = 0;
                break;
            default:
                fprintf(stderr, "Unrecognised msg type (%s)\n", __func__);
                break;
        }

        end:

        if (!err) {
            info.status = STATUS_MSG_OK;
        }

        if (msgsnd(mysqid, &info, sizeof(ubpf_queue_info_msg_t), 0) != 0) {
            perror("Can't send confirmation message to the ");
        }

    }
    return 0;
}

void remove_xsi() {

    size_t i, size;
    char r_path[PATH_MAX], conc_path[PATH_MAX];

    if (msgctl(msqid_listener, IPC_RMID, NULL) == -1) {
        perror("Can't remove message queue");
    }
    close_shared_memory();

    // unlink files
    const char *t[] = {QUEUEID, SHAREDID};
    size = sizeof(t) / sizeof(t[0]);
    for (i = 0; i < size; i++) {
        memset(r_path, 0, PATH_MAX * sizeof(char));
        memset(conc_path, 0, PATH_MAX * sizeof(char));
        snprintf(conc_path, PATH_MAX - 1, "%s/%s", daemon_vty_dir, t[i]);
        realpath(conc_path, r_path);
        if (unlink(r_path) != 0) {
            perror("Unlink failed");
        }
    }
    //
    rm_ipc();
}

static inline int write_id(const char *folder, int msg_queue_id, const char *shm_id) {
    // write the random string AND the message queue ID
    int fd_shared, fd_msgqueue;
    char path[PATH_MAX], path2[PATH_MAX], r_path[PATH_MAX];
    int nb_char;
    char buf[10];

    memset(path, 0, sizeof(char) * PATH_MAX);
    memset(path2, 0, sizeof(char) * PATH_MAX);

    snprintf(path, PATH_MAX, "%s/%s", folder, QUEUEID);
    snprintf(path2, PATH_MAX, "%s/%s", folder, SHAREDID);
    memset(r_path, 0, sizeof(char) * PATH_MAX);
    realpath(path, r_path);
    fd_msgqueue = open(r_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);

    if (fd_msgqueue == -1) {
        perror("Can't create queue.id");
        return -1;
    }
    memset(r_path, 0, sizeof(char) * PATH_MAX);
    realpath(path2, r_path);
    fd_shared = open(r_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);

    if (fd_shared == -1) {
        perror("Can't create shared.id");
        return -1;
    }

    memset(buf, 0, 10);
    nb_char = snprintf(buf, 10, "%d", msg_queue_id);

    if (full_write(fd_msgqueue, buf, nb_char) == -1) {
        perror("Can't write to queue.id");
        return -1;
    }
    if (full_write(fd_shared, shm_id, NAME_MAX) == -1) {
        perror("Can't write to shared.id");
        return -1;
    }

    close(fd_msgqueue);
    close(fd_shared);
    return 0;
}