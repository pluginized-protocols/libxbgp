//
// Created by thomas on 28/05/19.
//




#include <stdlib.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

FILE *data = NULL;

typedef struct mesg_buffer {
    long mesg_type;
    char mesg_text[20];
} ebpf_message_t;

struct announce_msg {
    clock_t clock;
    uint32_t type;
};


void sigint_handler(int signal_hdlr) {

    if(data) {
        fflush(data);
        fclose(data);
    }

    exit(EXIT_SUCCESS);

}

int main(void) {

    key_t key;
    int msgid;
    ebpf_message_t msg;
    struct announce_msg a;
    char buf_wrt[65];
    FILE * fp;


    fp = fopen ("/tmp/recv_data.txt","w");
    if(!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    data = fp; // to correctly close file (flush then close)

    if(signal(SIGINT, sigint_handler) == SIG_ERR){
        perror("signal transfer failure");
        return EXIT_FAILURE;
    }


    if((key = ftok("/var/run/frr", 65)) == -1) {
        perror("ftok");
        return EXIT_FAILURE;
    }

    if((msgid = msgget(key, 0666)) < 0) {
        perror("msgget");
        return EXIT_FAILURE;
    }

    for(;;) {
        if( (msgrcv(msgid, &msg, sizeof(ebpf_message_t), 0, 0)) == -1) {
            perror("Queue");
            return EXIT_FAILURE;
        }

        memset(buf_wrt, 0, sizeof(char) * 65);
        memcpy(&a, &msg.mesg_text, sizeof(struct announce_msg));
        snprintf(buf_wrt, 64, "{\"time\": %ld, \"type\": %d}\n", a.clock, a.type);

        if(fwrite(buf_wrt, sizeof(char), strnlen(buf_wrt, 65), fp) <= 0) {
            perror("write");
            return EXIT_FAILURE;
        }

    }

    fprintf(stderr, "ERROR SHOULD NOT BE THERE\n");
    return EXIT_FAILURE;
}