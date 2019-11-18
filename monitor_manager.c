//
// Created by thomas on 3/11/18.
//

#include "ubpf_tools/monitor_manager.h"
#include <ubpf_tools/ubpf_api.h>

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include "ubpf_tools/queue.h"



typedef struct args_receive_data {
    int socket_listen;
    queue_t *monitoring_queue;
    struct args_receive_data *this; // used to free resource inside detached thread
} args_receive_data_t;

int init_monitoring_server(int *listen_fd) {

    if (!listen_fd) {
        return 0;
    }

    struct sockaddr_un addr = {AF_UNIX, SOCKET_PATH};
    *listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    // we use a sock_stream to keep the connection open with the plugin
    // until server process this specific plugin. Otherwise, data sent
    // will be indefinitely lost.

    if (*listen_fd == -1) {
        perror("Unable to create unix socket");
        return 0;
    }

    unlink(SOCKET_PATH); // make sure that socket is removed from a previous start

    if (bind(*listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind unix socket");
        return 0;
    }

    if (listen(*listen_fd, SOMAXCONN) == -1) {
        perror("Cannot listen to unix socket");
        return 0;
    }

    return 1;

}

/**
 * Create a new structure containing all the needed arguments
 * to handle a new connexion from a remote process
 * @param monitoring_queue pointer related to the concurrent queue (used to process monitoring data)
 * @param client_socket socket related to the established connexion between remote process and this monitor
 * @return the pointer related to the allocated structure. NULL is out of memory.
 */
static args_receive_data_t *create_args_thread(queue_t *monitoring_queue, int client_socket) {

    args_receive_data_t *args;

    args = malloc(sizeof(args_receive_data_t));

    if (!args) {
        perror("Can't init args structure for \"receiving\" thread\n");
        return NULL;
    }

    args->monitoring_queue = monitoring_queue;
    args->socket_listen = client_socket;
    args->this = args;

    return args;

}

int start_monitor2(queue_t *monitoring_queue, int fd_read) {

    ssize_t len;
    size_t cumulative_length;
    size_t total_length;
    uint32_t type;
    uint8_t *recv_buf;
    data_t data;


    while(1) {


        memset(&total_length, 0, sizeof(uint32_t));
        memset(&type, 0, sizeof(uint16_t));
        memset(&data, 0, sizeof(data_t));

        len = read(fd_read, &total_length, sizeof(size_t)); // receive the first part of the packet: length

        if (len <= 0) {
            perror("error read pipe");
            exit(EXIT_FAILURE);
        }

        len = read(fd_read, &type, sizeof(uint32_t)); // receive the second part of the packet: type

        if (len <= 0) {
            perror("error read pipe");
            continue;
        }

        /* now headers has been read -> need to read the real data ! */

        cumulative_length = 0;
        recv_buf = malloc(total_length);
        if (!recv_buf) return 0; // unable to allocate memory

        while (cumulative_length < total_length) {
            len = read(fd_read, recv_buf + cumulative_length, total_length - cumulative_length);

            if (len <= 0) {
                perror("Error when receiving data");
                return 0;
            }
            cumulative_length += len;
        }


        data.data = recv_buf;
        data.type = type;
        data.length = total_length;

        enqueue(monitoring_queue, &data);

    }

    return 0;

}

int start_monitor(queue_t *monitoring_queue) {

    int socket_fd;
    int new_socket;
    pthread_t thread_co;
    pthread_attr_t attr;
    args_receive_data_t *args;

    data_t info_monitor;

    memset(&info_monitor, 0, sizeof(data_t));
    memset(&attr, 0, sizeof(pthread_attr_t));
    memset(&socket_fd, 0, sizeof(int));

    if (pthread_attr_init(&attr) != 0) return 0;

    if (!init_monitoring_server(&socket_fd)) {
        return 0;
    }

    if (pthread_attr_setdetachstate(&attr, 1) != 0) return 0;

    while (1) {

        new_socket = accept(socket_fd, NULL, NULL);
        if (new_socket < 0) // give up this connexion, concerned process will reattempt later
            perror("Cannot accept incoming connection");
        else {
            args = create_args_thread(monitoring_queue, new_socket);
            if (!args) {
                return 0; // maybe it's a bit to aggressive
            }

            if (pthread_create(&thread_co, &attr, &receive_data, (void *) args) != 0) {
                perror("Unable to handle new incoming connection thread failure");
                return 0;
            }

            memset(&thread_co, 0, sizeof(pthread_t));
        }

    }


}


void *receive_data(void *args) {

    args_receive_data_t *arguments = args;

    int client_socket = arguments->socket_listen;
    queue_t *monitoring_queue = arguments->monitoring_queue;

    ssize_t len;
    size_t cumulative_length;
    size_t total_length;
    uint32_t type;
    uint8_t *recv_buf;
    data_t data;


    memset(&total_length, 0, sizeof(uint32_t));
    memset(&type, 0, sizeof(uint16_t));
    memset(&data, 0, sizeof(data_t));

    len = recv(client_socket, &total_length, sizeof(size_t), 0); // receive the first part of the packet: length

    if (len <= 0) {
        perror("Connection closed by remote host");
        close(client_socket);
        pthread_exit(0);
    }

    len = recv(client_socket, &type, sizeof(uint32_t), 0); // receive the second part of the packet: type

    if (len <= 0) {
        perror("Connection closed by remote host");
        close(client_socket);
        pthread_exit(0);
    }

    /* now headers has been read -> need to read the real data ! */


    cumulative_length = 0;
    recv_buf = malloc(total_length);
    if (!recv_buf) return (void *) 0; // unable to allocate memory

    while (cumulative_length < total_length) {
        len = recv(client_socket, recv_buf + cumulative_length, total_length - cumulative_length, 0);

        if (len <= 0) {
            perror("Error when receiving data");
            close(client_socket);
            pthread_exit(0);
        }
        cumulative_length += len;
    }


    if (shutdown(client_socket, SHUT_RDWR) < 0) {
        perror("Shutdown socket");
    }
    if (close(client_socket) < 0) {
        perror("Can't close socket");
    }

    data.data = recv_buf;
    data.type = type;
    data.length = total_length;

    enqueue(monitoring_queue, &data);

    //free(recv_buf);
    free(arguments->this);

    pthread_exit(0);
}