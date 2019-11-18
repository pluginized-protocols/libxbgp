//
// Created by thomas on 1/01/19.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ubpf_tools/ipfix_collector.h"

#define MAX_PORTCHARLEN 6
#define MAX_IPV4CHARLEN 16
#define MAX_NAME 71

static inline void usage(char *prog_name) {

    if(!prog_name){
        fprintf(stderr, "Internal error\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr,
            "IPFIX collector (if two same arguments is passed to the program,"
            "the last seen is the one taken into account)\n"
            "Usage: %s [-p ipfix_port] [-l ipfix_listen] [-m mongo_addr] [-n mongo_port] -c coll_name -d db_name\n"
            "\t[-p ipfix_port] : listening port of this ipfix collector (default 4739)\n"
            "\t[-i ipfix_listen] : address the collector has to listen (default all) IPv4 only\n"
            "\t[-m mongo_addr] : address of the database (default localhost) IPv4 only\n"
            "\t[-n mongo_port] : port from which db is listening to (default 27017)\n"
            "\t-c coll_name : name of the mongoDB collection where ipfix msg will be stored\n"
            "\t-d db_name : mongoDB database name where ipfix msg will be stored\n",
            prog_name);
}

int main(int argc, char *argv[]) {

    int opt, err;

    char ipfix_port[MAX_PORTCHARLEN];
    char ipfix_listen[MAX_IPV4CHARLEN];
    char mongo_addr[MAX_IPV4CHARLEN];
    char mongo_port[MAX_PORTCHARLEN];
    char db_name[MAX_NAME];
    char coll_name[MAX_NAME];
    char mongo_uri[MAX_NAME];

    int c_opt;
    int d_opt;
    char *ipfix_listen_ptr; // if NULL, all interfaces must be listened


    memset(ipfix_listen, 0, sizeof(ipfix_listen));
    memset(ipfix_port, 0, sizeof(ipfix_port));
    memset(mongo_addr, 0, sizeof(mongo_addr));
    memset(mongo_port, 0, sizeof(mongo_port));
    memset(db_name, 0, sizeof(db_name));
    memset(coll_name, 0, sizeof(coll_name));
    memset(mongo_uri, 0, sizeof(mongo_uri));

    /* set default values */
    strncpy(ipfix_port, "4739", 5);
    strncpy(mongo_addr, "localhost", 10);
    strncpy(mongo_port, "27017", 6);
    ipfix_listen_ptr = NULL;

    c_opt = 0;
    d_opt = 0;
    err = 0;


    /**
     * -p ipfix listen port
     * -i ipfix listen interface
     * -m mongo address
     * -n mongo port
     * -c mongo collection name
     * -d mongo db name
     */
    while ((opt = getopt(argc, argv, "p:i:m:n:c:d:")) != -1) {
        switch (opt) {
            case 'p':
                strncpy(ipfix_port, optarg, MAX_PORTCHARLEN-1);
                break;
            case 'i':
                strncpy(ipfix_listen, optarg, MAX_IPV4CHARLEN-1);
                ipfix_listen_ptr = ipfix_listen;
                break;
            case 'm':
                strncpy(mongo_addr, optarg, MAX_IPV4CHARLEN-1);
                break;
            case 'n':
                strncpy(mongo_port, optarg, MAX_PORTCHARLEN-1);
                break;
            case 'c':
                c_opt = 1;
                strncpy(coll_name, optarg, MAX_NAME-1);
                break;
            case 'd':
                d_opt = 1;
                strncpy(db_name, optarg, MAX_NAME-1);
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!c_opt) {
        err++;
        fprintf(stderr, "MongoDB collection name is missing (-c coll_name)\n");
    }
    if (!d_opt) {
        err++;
        fprintf(stderr, "MongoDB database name is missing (-d db_name)\n");
    }
    if (err) {
        fprintf(stderr, "%i error(s) found\n", err);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    snprintf(mongo_uri, MAX_NAME, "mongodb://%s:%s", mongo_addr, mongo_port);

    if(start_collector(ipfix_listen_ptr, ipfix_port, db_name, coll_name, mongo_uri) < 0){
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}