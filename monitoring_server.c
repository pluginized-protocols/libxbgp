//
// Created by thomas on 4/11/18.
//

#include "backup_code/bgp_ipfix.h"
#include "monitoring_server.h"
#include "plugins_manager.h"
#include "queue.h"
#include "map.h"
#include "list.h"

#include <sys/socket.h>
#include <netinet/in.h>

// 1MB
#define MAX_BUFFER_SIZE 1048576

struct __attribute__((__packed__)) header_aggregate {
    uint32_t nb_tlv;
};


enum error_monit {
    OK = 0,
    CONN_ERROR,
    MEM_ERROR,
    THREAD_ERROR,
    NOT_INIT_ERROR,
};

static queue_t *monit_queue;
static int server_fd = -1;

/*
 * 0: monitoring can be active but not mandatory
 * 1: monitoring is required
 */
static int require_monit = 0;

struct monitor_loop_args {
    queue_t *monitoring_data;
    int fd_read;
};

int is_monit_required() {
    return require_monit;
}

int has_monit_fd() {
    return server_fd == -1 ? 0 : 1;
}

static int establish_connexion(const char *host, const char *port) {

    int yes = 1;
    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *res, *p;
    int sfd = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    if ((status = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
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

    if (!res) return -1;
    status = connect(sfd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(servinfo);
    return status == -1 ? -1 : sfd;
}

int open_exporter_connexion(const char *host, const char *port, int force) {

    int sfd;
    if (server_fd != 1) {
        if (!force) return 0;
        else {
            close(server_fd);
            server_fd = -1;
        }
    }
    sfd = establish_connexion(host, port);

    if (sfd == -1) return -1;
    server_fd = sfd;
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

    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    require_monit = monit;

    pid = fork();
    if(pid == -1) {
        perror("Cannot fork");
        return -1;
    } else if (pid == 0) { // child
        // init monitoring
        close(pipe_fd[1]);
        status = main_monitor(address, port, pipe_fd[0]);

        if (status == CONN_ERROR && monit) {
            exit(EXIT_SUCCESS);
        } else  {
            fprintf(stderr, "Unable to launch monitoring server\n");
            exit(EXIT_FAILURE); // shouldn't be reached
        }
    } else { // parent
        close(pipe_fd[0]);
        set_write_fd(pipe_fd[1]);
        return pipe_fd[1];
    }
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

    monit_queue = init_queue(sizeof(data_t));
    int *fd;
    struct monitor_loop_args *args;

    if (monit_queue == NULL) {
        return NOT_INIT_ERROR;
    }

    if(open_exporter_connexion(address, port, 0) == -1) {
        return CONN_ERROR;
    }

    fd = malloc(sizeof(int));
    if (!fd) return MEM_ERROR;
    args = malloc(sizeof(struct monitor_loop_args));
    if (!args) {
        free(fd);
        return MEM_ERROR;
    }
    *fd = fd_read;
    args->fd_read = fd_read;
    args->monitoring_data = monit_queue;

    pthread_t thread_data;
    pthread_t agg_data;

    if (pthread_create(&thread_data, NULL, &monitor_loop, NULL) != 0) {
        perror("Can't create thread (data receiver)");
        return THREAD_ERROR;
    }

    if (pthread_create(&agg_data, NULL, &aggregate_data, NULL) != 0) {
        perror("Can'y create thread (data aggregator)");
        return THREAD_ERROR;
    }

    if (pthread_join(thread_data, NULL) != 0) {
        perror("Thread join failure");
        return THREAD_ERROR;
    }

    return 0;
}

void *aggregate_data(void *args) {

    uint8_t *buffer;
    buffer = malloc(MAX_BUFFER_SIZE);
    unsigned int index;
    unsigned int curr_len;
    int nb_record;

    data_t tlv_record;

    if (!buffer) {
        perror("Cannot allocate memory");
    }

    index = sizeof(struct header_aggregate);
    nb_record = 0;

    while (1) {

        if (!dequeue(monit_queue, &tlv_record)) continue;
        curr_len = header_tlv_size + tlv_record.length;

        if (index + curr_len >= MAX_BUFFER_SIZE) {
            // send to exporter, that will send to the collector and then DB...
            struct header_aggregate *hdr = (struct header_aggregate *) buffer;
            hdr->nb_tlv = htonl(nb_record);
            if (send_to_exporter(buffer, index) == -1) return 0;
            // reset index
            index = sizeof(struct header_aggregate);
        }

        memcpy(buffer + index, &tlv_record, curr_len);
        index += curr_len;
        nb_record++;
    }
}

void *monitor_loop(void *args) {


    struct monitor_loop_args *cast_args = args;

    int fd_read = cast_args->fd_read;
    queue_t *monitoring_queue = cast_args->monitoring_data;

    ssize_t len;
    size_t cumulative_length;
    uint8_t *recv_buf;

    data_t record;

    while (1) {

        memset(&record, 0, sizeof(record));
        cumulative_length = 0;

        len = read(fd_read, &record.length, sizeof(size_t)); // receive the first part of the packet: length

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

        enqueue(monitoring_queue, &record);
    }
    return 0;
}