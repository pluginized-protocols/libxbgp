//
// Created by cyril on 17/11/18.
//

#ifndef PROJECT_PLUGINS_H
#define PROJECT_PLUGINS_H

/* All these includes should be removed. The only include plugins should have is the ospf_plugins_api.h
 * Although for the moment we keep them, it helps to have access to OSPF macros / define otherwise we have to hardcode the values
 */

#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "defaults.h" // avoid autoconf error
#include "prefix.h"
#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_flood.h"

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "pqueue.h"
#include "memory.h"
#include "memory_vty.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "../../ubpf/tools/ospf_plugins_api.h"
#include "../monitoring_server/monitoring_server.h"


#define RED 1
#define GREEN 2


#endif //PROJECT_PLUGINS_H
