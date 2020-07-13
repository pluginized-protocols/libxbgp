//
// Created by thomas on 4/11/18.
//

#include "monitoring_server.h"
#include "plugins_manager.h"
#include "queue.h"
#include "map.h"
#include "list.h"
#include "ubpf_misc.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <wait.h>

// 1MB
#define MAX_BUFFER_SIZE 1048576

struct __attribute__((__packed__)) header_aggregate {
    uint32_t nb_tlv;
};

struct last_send {
    struct timespec last;
};

typedef struct buffer {
    uint8_t buffer[MAX_BUFFER_SIZE];
    atomic_int len; // require C11 !
    uint32_t nb_record;
} buffer_t;

static queue_t *monit_queue;
static queue_t *ready_data;
static buffer_t current_buffer;


static int server_fd = -1;

/*
 * 0: monitoring can be active but not mandatory
 * 1: monitoring is required
 */
static int require_monit = 0;

pthread_t thread_rec;
pthread_t thread_send;
pthread_t thread_aggregate;
pthread_t thread_check_data;
pid_t child_pid = -1;

pthread_mutex_t mutex_connexion; // in case of connexion reestablishment, block the sending of data
pthread_mutex_t mutex_curr_buf; //on time out
struct last_send last_send;

struct monitor_loop_args {
    queue_t *monitoring_data;
    int fd_read;
};

struct sender_th_args {
    uint8_t *buffer;
    size_t *max_size;
};


int is_monit_required() {
    return require_monit;
}

int has_monit_fd() {
    return server_fd == -1 ? 0 : 1;
}

static void sig_handler(int signo) {
    if (signo != SIGINT) return;

    wait_monitoring();

    exit(EXIT_SUCCESS);
}

static inline void timespec_diff(struct timespec *start, struct timespec *stop,
                                 struct timespec *result) {
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
}


static inline int lesser(const struct timespec *lhs, const struct timespec *rhs) {
    if (lhs->tv_sec == rhs->tv_sec)
        return lhs->tv_nsec < rhs->tv_nsec;
    else
        return lhs->tv_sec < rhs->tv_sec;
}

//// WTF ?
static __attribute__((unused)) void init_last_send(struct last_send *ls) {

    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
        perror("Error, cannot get system clock");
        return;
    }

    memcpy(&ls->last, &tp, sizeof(struct timespec));
    // memcpy(&ls->previous, &tp, sizeof(struct timespec));
}

static int establish_connexion(const char *host, const char *port) {

    int yes = 1;
    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *res, *p;
    int sfd = -1;

    if (host == NULL) {
        // fprintf(stderr, "No host name specified\n");
        return -1;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    if ((status = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s (host %s, port %s)\n", gai_strerror(status), host, port);
        return -1;
    }

    res = NULL;
    for (p = servinfo; p != NULL && res == NULL; p = p->ai_next) {

        if (p->ai_family == AF_INET || p->ai_family == AF_INET6) { // IPv4 or IPv6
            sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sfd == -1) {
                perror("Socket");
                return -1;
            }
            res = p;
        }
    }

    if (setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        perror("Cannot enable keepalive");
        return -1;
    }

    if (!res) {
        fprintf(stderr, "the error :'(\n");
        return -1;
    }
    status = connect(sfd, res->ai_addr, res->ai_addrlen);
    if (status == -1) {
        perror("Connection with host failed");
    }
    freeaddrinfo(servinfo);
    return status == -1 ? -1 : sfd;
}

int open_exporter_connexion(const char *host, const char *port, int force) {

    int sfd;
    pthread_mutex_lock(&mutex_connexion);
    {
        if (server_fd != -1) {
            if (!force) {
                return 0;
            } else {
                close(server_fd);
                server_fd = -1;
            }
        }

        sfd = establish_connexion(host, port);

        if (sfd == -1) return -1;
        server_fd = sfd;
    }
    pthread_mutex_unlock(&mutex_connexion);

    return 0;
}

void close_exporter_connexion() {
    if (server_fd != -1) return;
    close(server_fd);
}

int init_monitoring(const char *address, const char *port, int monit) {

    int pipe_fd[2];
    int status;
    pid_t pid;

    // pipe_fd[0] read
    // pipe_fd[1] write

    monit_queue = init_queue(sizeof(data_t));
    ready_data = init_queue(sizeof(uint8_t *));

    if (monit_queue == NULL || ready_data == NULL) {
        return NOT_INIT_ERROR;
    }


    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    require_monit = monit;

    pid = fork();
    if (pid == -1) {
        perror("Cannot fork");
        return -1;
    } else if (pid == 0) { // child
        // init monitoring
        close(pipe_fd[1]);

        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            perror("Cannot overwrite SIGINT signal handler");
        };

        if (pthread_mutex_init(&mutex_connexion, NULL) != 0) {
            perror("Mutex init error");
            exit(EXIT_FAILURE);
        }
        if (pthread_mutex_init(&mutex_curr_buf, NULL) != 0) {
            perror("Mutex init error");
            exit(EXIT_FAILURE);
        }

        status = main_monitor(address, port, pipe_fd[0]);
        child_pid = -1;

        if (CONN_ERROR == status) {
            if (monit) {
                fprintf(stderr, "Unable to launch monitoring server\n");
                exit(EXIT_FAILURE);
            } else {
                exit(EXIT_SUCCESS);
            }
        }

        exit(EXIT_FAILURE);
    } else { // parent
        child_pid = pid;
        close(pipe_fd[0]);
        //set_write_fd(pipe_fd[1]);
        return pipe_fd[1];
    }
}

void turnoff_monitoring() {

    int status;

    if (child_pid == -1) return;
    kill(child_pid, SIGINT);
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("Can't wait process termination");
        return;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[Warning] Monitoring process not gracefully exited!\n");
        kill(child_pid, SIGKILL);
    }

    pthread_mutex_destroy(&mutex_curr_buf);
    pthread_mutex_destroy(&mutex_connexion);
    memset(&mutex_curr_buf, 0, sizeof(pthread_mutex_t));
    memset(&mutex_connexion, 0, sizeof(pthread_mutex_t));
}

int send_to_exporter(uint8_t *buffer, size_t len) {

    ssize_t byte_sent;
    size_t cumul_sent = 0;
    if (server_fd == -1) return -1;

    while (cumul_sent < len) {
        byte_sent = send(server_fd, buffer + cumul_sent, len - cumul_sent, 0);

        if (byte_sent == -1) {
            perror("Send failed");
            return -1;
        }
        cumul_sent += byte_sent;
    }
    return 0;
}

int main_monitor(const char *address, const char *port, int fd_read) {


    struct monitor_loop_args *args;
    memset(&current_buffer, 0, sizeof(buffer_t));

    if (open_exporter_connexion(address, port, 0) == -1) {
        return CONN_ERROR;
    }

    args = malloc(sizeof(struct monitor_loop_args));
    if (!args) return MEM_ERROR;

    args->fd_read = fd_read;
    args->monitoring_data = monit_queue;

    if (pthread_create(&thread_rec, NULL, &monitor_loop, args) != 0) {
        perror("Cannot create thread (data receiver)");
        return THREAD_ERROR;
    }

    if (pthread_create(&thread_aggregate, NULL, &aggregate_data, NULL) != 0) {
        perror("Cannot create thread (data aggregator)");
        return THREAD_ERROR;
    }

    if (pthread_create(&thread_send, NULL, &data_loop_sender, NULL) != 0) {
        perror("Cannot create thread (data send)");
        return THREAD_ERROR;
    }

    if (pthread_create(&thread_check_data, NULL, &check_curr_buffer, NULL) != 0) {
        perror("Cannot create thread (data check)");
        return THREAD_ERROR;
    }

    if (pthread_join(thread_rec, NULL) != 0) {
        perror("Thread join failure");
        return THREAD_ERROR;
    }

    if (pthread_join(thread_send, NULL) != 0) {
        perror("Thread join failure");
        return THREAD_ERROR;
    }

    return 0;
}

void *aggregate_data(void *args) {

    ((void) args);

    buffer_t *buffer;
    unsigned int curr_len;

    data_t tlv_record;

    current_buffer.len = sizeof(struct header_aggregate);

    while (1) {
        if (!dequeue(monit_queue, &tlv_record)) {
            fprintf(stderr, "Can't dequeue\n");
            continue;
        }
        curr_len = header_tlv_size + ntohl(tlv_record.length);

        if (pthread_mutex_lock(&mutex_curr_buf) != 0) return NULL;
        {
            if (current_buffer.len + curr_len >= MAX_BUFFER_SIZE) {
                buffer = malloc(sizeof(buffer_t));
                memcpy(buffer, &current_buffer, sizeof(buffer_t));

                struct header_aggregate *hdr = (struct header_aggregate *) buffer->buffer;
                hdr->nb_tlv = htonl(current_buffer.nb_record);
                enqueue(ready_data, &buffer);
                current_buffer.len = sizeof(struct header_aggregate);
                current_buffer.nb_record = 0;
            }

            memcpy(current_buffer.buffer + current_buffer.len, &tlv_record.type, sizeof(uint32_t));
            current_buffer.len += sizeof(uint32_t);
            memcpy(current_buffer.buffer + current_buffer.len, &tlv_record.length, sizeof(uint32_t));
            current_buffer.len += sizeof(uint32_t);
            memcpy(current_buffer.buffer + current_buffer.len, tlv_record.value, ntohl(tlv_record.length));
            current_buffer.len += ntohl(tlv_record.length);
            current_buffer.nb_record++;
            free(tlv_record.value);
            tlv_record.value = NULL;
        }
        if (pthread_mutex_unlock(&mutex_curr_buf) != 0) return NULL;
    }


    return NULL;
}

/**
 * Sends data as long as the queue is not empty
 * @param _args
 * @return
 */
void *data_loop_sender(void *_args __attribute__((unused))) {
    buffer_t *data;
    //struct sender_th_args *args = _args;
    struct timespec tv = {.tv_sec = 60, .tv_nsec = 0}; // todo change magic number
    struct timespec curr_time;


    while (1) {
        if (nanosleep(&tv, NULL) != 0) {
            perror("Can't retrieve time");
            return NULL;
        }

        dequeue(ready_data, &data);
        if (pthread_mutex_lock(&mutex_curr_buf) != 0) return NULL;
        {
            if (send_to_exporter(data->buffer, data->len) == -1) {} // todo
            clock_gettime(CLOCK_MONOTONIC, &curr_time);
            last_send.last = curr_time;
        }
        if (pthread_mutex_unlock(&mutex_curr_buf) != 0) return NULL;
        data = NULL;

    }

    return NULL;
}

/**
 * If plugins send few monitoring data, checks if there is some data
 * The check is done periodically in a rate (TODO) given by the user
 * @param _args
 * @return
 */
void *check_curr_buffer(void *_args __attribute__((unused))) {

    struct timespec curr_time;
    struct timespec tv = {.tv_sec = 180, .tv_nsec = 0}; // todo remove magic numbers

    while (1) {

        if (nanosleep(&tv, NULL) != 0) {
            perror("Cannot sleep");
            return NULL;
        }

        if (current_buffer.len > 0 && q_size(ready_data) == 0) {
            // should have 1) sthg to send and 2) no pending data to be sent

            clock_gettime(CLOCK_MONOTONIC, &curr_time);

            if (lesser(&last_send.last, &curr_time)) { // time to send
                flush_buffer();
            }
        }

    }
    return NULL;
}

/**
 * Force the current buffer to be sent to the exporter.
 * To be used in the current process only !
 * @return -1 if failed. 0 otherwise
 */
int flush_buffer() {

    struct timespec curr_time;

    if (pthread_mutex_lock(&mutex_curr_buf) != 0) return -1;
    {
        struct header_aggregate *hdr = (struct header_aggregate *) current_buffer.buffer;
        hdr->nb_tlv = htonl(current_buffer.nb_record);

        if (current_buffer.len <= 0) {
            fprintf(stderr, "No data to send\n");
            return 0; // don't send anything
        }

        if (send_to_exporter(current_buffer.buffer, current_buffer.len) == -1) {
            fprintf(stderr, "Unable to send records\n");
        } // todo
        if (clock_gettime(CLOCK_MONOTONIC, &curr_time) != 0) {
            perror("Cannot retrieve time");
            return -1;
        }
        last_send.last = curr_time;
        memset(&current_buffer, 0, sizeof(buffer_t));
        current_buffer.len = sizeof(struct header_aggregate);
        current_buffer.nb_record = 0;
    }
    if (pthread_mutex_unlock(&mutex_curr_buf) != 0) return -1;

    return 0;
}


void wait_monitoring() {

    struct timespec tv = {.tv_sec = 2, .tv_nsec = 0};

    while (q_size(ready_data) > 0) { // busy wait until all records has been sent
        if (nanosleep(&tv, NULL) != 0) {
            perror("Unable to sleep");
        }
    }

    flush_buffer();
}

void *monitor_loop(void *args) {

    struct monitor_loop_args *cast_args = args;

    int fd_read = cast_args->fd_read;
    queue_t *monitoring_queue = cast_args->monitoring_data;

    ssize_t len;
    size_t cumulative_length;
    uint8_t *recv_buf;

    data_t record;

    free(args);

    while (1) {

        memset(&record, 0, sizeof(record));
        cumulative_length = 0;

        len = read(fd_read, &record.length, sizeof(uint32_t)); // receive the first part of the packet: length

        if (len <= 0) {
            perror("error read pipe");
            exit(EXIT_FAILURE);
        }

        len = read(fd_read, &record.type, sizeof(uint32_t)); // receive the second part of the packet: type

        if (len <= 0) {
            perror("error read pipe");
            continue;
        }

        /* now headers has been read -> need to read the real data ! */
        recv_buf = malloc(record.length);
        if (!recv_buf) return 0; // unable to allocate memory

        while (cumulative_length < record.length) {
            len = read(fd_read, recv_buf + cumulative_length, record.length - cumulative_length);

            if (len <= 0) {
                perror("Error when receiving data");
                return 0;
            }
            cumulative_length += len;
        }

        // change to network order before enqueuing
        record.type = htonl(record.type);
        record.length = htonl(record.length);
        record.value = recv_buf;

        enqueue(monitoring_queue, &record);
    }
    return 0;
}