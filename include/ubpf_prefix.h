//
// Created by thomas on 29/05/20.
//

#ifndef UBPF_TOOLS_PREFIX_H
#define UBPF_TOOLS_PREFIX_H

#include <netinet/in.h>

#define MAX_STR_BUF_PFX 45

struct prefix_ip6 {
    int family;
    int prefix_len;
    struct in6_addr p;
};

struct prefix_ip4 {
    int family;
    int prefix_len;
    struct in_addr p;
};

union ubpf_prefix {

    int family;

    struct prefix_ip4 ip4_pfx;
    struct prefix_ip6 ip6_pfx;
};

#endif //UBPF_TOOLS_PREFIX_H
