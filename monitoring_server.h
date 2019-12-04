//
// Created by thomas on 4/11/18.
//

#ifndef FRR_THESIS_MONITORING_SERVER_H
#define FRR_THESIS_MONITORING_SERVER_H


#include <semaphore.h>
#include <stdint.h>

#define header_tlv_size 8u

typedef struct tlv_record {
    uint32_t type;
    uint32_t length; // length of value field in bytes.
    uint8_t *value;
} data_t;


void *send_to_collector(void *args);

/**
 * When a new data is dequeued from the concurrent queue
 * (see @top_dir@/ubpf_tools/queue.h) this function will
 * cast the data_t (see @top_dir@/ubpf_tools/monitor_manager.h)
 * structure into the right structure (@see @top_dir@/ubpf_tools/include/monitoring_struct.h)
 * given the type stored inside this structure (data_t).
 *
 * Once the data is correctly transformed into the right
 * structure, the function will update the global monitoring state
 * (see above monit_state_t structure)
 *
 * @param data dequeued packet from the global concurrent queue.
 * @return 1 if operation succeeded
 *         0 todo
 */
int data_handling(data_t *data);

/**
 * Create the monitoring server. Typically, the monitor
 * is divided into two main thread which are launched
 * inside the BGP process.
 * The first thread handles the connection part. That is,
 * it will wait and accept for new connections. Once a
 * connexion is accepted, the client will sends its data.
 * Once this step is done, the thread will transfer this data
 * to the concurrent queue to the second thread.
 * (see launch_monitoring function below)
 *
 * This second thread will thus dequeue an item of the concurrent
 * queue. Then, according to the type of data, the general state
 * is updated (see above monit_state_t structure).
 * see processing_data below.
 *
 *
 * To achieve this such task a lot of things are done :
 *     1. initialize the concurrent queue used by both threads
 *     2. create the thread for the connection part
 *     3. create the thread for the data handling part
 *     4. set these to thread in detached state
 *
 * @return 1 if operation succeed
 *         0 otherwise ( - unable to launch threads )
 */
int main_monitor(const char *address, const char *port, int fd_read);

/**
 * Thread processing a new monitoring data sent by an uBPF
 * plugin and update the current monitoring state.
 * monitoring data are inserted by the thread will handles
 * the connection part of the monitoring server. Hence, if
 * no data are sent, this thread will wait until new data
 * contained in the queue.
 * Once a new data is dequeued, this popped item will be
 * send to the function that will recognize the type of
 * monitoring data.
 *
 * @param args no arguments are sent to this thread
 * @return normally doesn't return, since it loops indefinitely
 */
void *processing_data(void *args);

/**
 * Thread managing the connection part of the monitor server.
 *
 * In order to achieve that, it will:
 *    1. create a new listening unix socket
 *    2. wait for incoming connection
 *    3. a new client is connected to the server
 *    4. client will upload its monitoring item
 *    5. server copy this data to the concurrent queue
 *       (used by the other thread)
 *
 * @param args nothing is passed to this thread
 * @return should not return since it will indefinitely loop.
 */
void *monitor_loop(void *args);

int open_exporter_connexion(const char *host, const char *port, int force);

void close_exporter_connexion();

int send_to_exporter(uint8_t *buffer, size_t len);

void *aggregate_data(void *args);

int init_monitoring(const char *address, const char *port, int require_monitoring);

int is_monit_required();

int has_monit_fd();

void turnoff_monitoring();

#endif //FRR_THESIS_MONITORING_SERVER_H
