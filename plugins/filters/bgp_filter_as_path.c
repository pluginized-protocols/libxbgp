//
// Created by thomas on 28/05/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgpd.h>

/**
 * ON IMPORT FILTER
 * Allowing route received from odd ASes
 * @return FILTER_ACCEPT if route has been learned from odd AS
 *         FILTER_DENY if route has been learned from even AS
 *         BGP_CONTINUE in case of error (OUT OF MEMORY)
 */
uint64_t filter_router_aspath(bpf_full_args_t *args) {

    as_t a = get_as_from_attr(args, 2);

    return a == 0 ? BGP_CONTINUE : (a % 2 == 0 ? FILTER_DENY : FILTER_PERMIT);
}