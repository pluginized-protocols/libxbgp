//
// Created by thomas on 3/11/18.
//

#ifndef FRR_THESIS_MONITOR_MANAGER_H
#define FRR_THESIS_MONITOR_MANAGER_H

#include "ubpf_tools/queue.h"
#include <fixbuf/public.h>

/**
 * This structure is the generic data sent to the monitor.
 * The type argument will distinguish what kind of structure the
 * data array is containing. (list of every types and structures could be
 * found at @top_dir@/ubpf_tools/include/monitoring_struct.h)
 */
typedef struct monitor_data {

    uint32_t type; // used to inform what kind of data uBPF plugin sends to monitor
    size_t length; // total length of data
    uint8_t *data; // WARNING, as data sent may be more or less large, we store it in the heap !!!!!

} data_t;

/**
 * Create a socket which is ready to listen for every incoming
 * connexion. The created socket is actually a UNIX_SOCKET since
 * the monitor is contained in the BGP process (inside its own thread)
 * @param listen_fd pointer to the memory which will receive the freshly
 *                  created socket in this function. Hence, listen_fd MUST NOT be NULL.
 * @return 1 if the socket is ready to listen incoming connexion
 *         0 otherwise ( unable to create the unix socket )
 */
int init_monitoring_server(int *listen_fd);

/**
 * Main loop of the monitoring server. This function will create
 * the monitoring server and wait for new incoming connexion. Once a
 * new connection is received, this function will create a thread which
 * is used to handle this particular connexion. Hence, the function is
 * only listening on its socket.
 *
 * @param q structure containing the concurrent queue used to append new
 *          data received from remote process.
 *
 * @return SHOULD NOT RETURN ANYTHING !! HOWEVER, IF IT IS THE CASE, SOMETHING
 *         WRONG HAPPENED. ( - unable to create new thread for incoming connexion,
 *                           - unable to create the listening socket. )
 */
int start_monitor(queue_t *q);
int start_monitor2(queue_t *monitoring_queue, int fd_read);

/**
 * This function handle the connexion between a particular client and the
 * monitor thread. This function runs inside its own thread. Therefore, its
 * argument is a pointer related to (in this case) a structure containing :
 *     - the socket related to the client
 *     - the concurrent queue used to add data uploaded by the client
 * This function is running inside a DETACHED thread, if something wrong
 * happen, client data will be lost. Usually, an error could happen if the
 * remote client early close the connexion.
 *
 *
 * ABOUT the protocol :
 *
 * The connexion must be established FIRST by the client. When the monitor accepts this connexion,
 * the client will first send the total length of the data (in a form of a 32bits integer *NB*: since we have
 * an inter process communication, this integer is not normalized via htonl function).
 * Once this step is reached, the client sends its structure thanks to the struct monitor_data
 * defined above.
 * Finally, when the monitor has successfully received the entire packet, it will then close the
 * connexion and the thread is destroyed.
 *
 * @return NOTHING
 */
void *receive_data(void *);

#endif //FRR_THESIS_MONITOR_MANAGER_H
