//
// Created by thomas on 27/08/21.
//

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ubpf_int.h>
#include <string.h>
#include <fcntl.h>
#include <ubpf_manager.h>
#include <plugins_manager.h>

#include <xbgp_compliant_api/xbgp_api_vars.h>
#include <xbgp_compliant_api/xbgp_defs.h>

/* set all xBGP api to extern function */
int add_attr(context_t *ctx, uint8_t code, uint8_t flags, uint16_t length, uint8_t *decoded_attr) {}

int set_attr(context_t *ctx, struct path_attribute *attr) {}

struct path_attribute *get_attr(context_t *ctx) {}

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len) {}

struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code) {}

struct path_attribute *get_attr_from_code_by_route(context_t *ctx, uint8_t code, int rte) {}

int announce_nrli(context_t *ctx, struct ubpf_prefix *pfx) {}

struct ubpf_peer_info *get_peer_info(context_t *ctx, int *nb_peers) {}

struct ubpf_peer_info *get_src_peer_info(context_t *ctx) {}

int set_peer_info(context_t *ctx, uint32_t router_id, int key, void *value, int len) {}

struct ubpf_prefix *get_prefix(context_t *ctx) {}

struct ubpf_nexthop *get_nexthop(context_t *ctx, struct ubpf_prefix *pfx) {}

struct ubpf_rib_entry *get_rib_in_entry(context_t *ctx, uint8_t af_family, struct ubpf_prefix *pfx) {}

struct bgp_route *get_rib_out_entry(context_t *ctx, uint8_t af_family,
                                    struct ubpf_prefix *pfx, struct ubpf_peer_info *pinfo) {}

struct ubpf_rib_entry *get_loc_rib_entry(context_t *ctx, uint8_t af_family, struct ubpf_prefix *pfx) {}

struct bgp_route *get_bgp_route(context_t *ctx, enum BGP_ROUTE_TYPE type) {}

int new_rib_iterator(context_t *ctx, int afi, int safi) {}

struct bgp_route *next_rib_route(context_t *ctx, unsigned int iterator_id) {}

int rib_has_route(context_t *ctx, unsigned int iterator_id) {}

void rib_iterator_clean(context_t *ctx, unsigned int iterator_id) {}

int remove_route_from_rib(context_t *ctx, struct ubpf_prefix *pfx, struct ubpf_peer_info *peer_info) {}

int get_vrf(context_t *ctx, struct vrf_info *vrf_info) {}

int schedule_bgp_message(context_t *ctx, int type, struct bgp_message *message, const char *peer_ip) {}

int peer_session_reset(context_t *ctx, const char *peer_ip) {}

/* end trick */


int count_ebpf_insts(const char *elf_file, int enable_memchecks, int *elf_inst, int *tot_insts);

void entry_point(const char *elf_file, int memchecks);

static inline void usage(const char *prog_name) {
    fprintf(stderr, "%s: count the total number of eBPF instructions contained in "
                    "the data section of the eBPF bytecode passed at arguments.\n"
                    "Usage: %s [-m] -e elf_file\n"
                    "-m           enable memory checks at run time\n"
                    "-e elf_file  use the elf file located at elf_file\n",
            prog_name, prog_name);
}

int count_ebpf_insts(const char *elf_file, int enable_memchecks, int *elf_inst, int *tot_insts) {
    vm_container_t *super_vm_de_ses_morts;
    void *data;
    long data_size;
    char dummy_space[16];
    int status;

    if (init_plugin_manager(api_funcs, ".", insertion_points, 0, NULL) != 0) {
        fprintf(stderr, "Unable to init plugin manager\n");
        return -1;
    }

    status = add_extension_code("dummy_plugin", 12, 8,
                                0, 1, "dummy_insertion_point", 21,
                                BPF_REPLACE, 0, 0, elf_file, 0,
                                "dummy_vm", 8, api_funcs, 0777, enable_memchecks);

    if (status != 0) {
        fprintf(stderr, "Unable to load xBGP program\n");
        return -1;
    }

    super_vm_de_ses_morts = vm_by_name("dummy_vm");
    if (!super_vm_de_ses_morts) {
        fprintf(stderr, "Unable to find the VM ?\n");
        return -1;
    }

    if (elf_inst) {
        *elf_inst = super_vm_de_ses_morts->vm->elf_insts;
    }
    if (tot_insts) {
        *tot_insts = super_vm_de_ses_morts->vm->num_insts;
    }

    ubpf_terminate();
    return 0;
}

void entry_point(const char *elf_file, int memchecks) {
    int elf_insts;
    int tot_insts;

    if (count_ebpf_insts(elf_file, memchecks, &elf_insts, &tot_insts) != 0) {
        exit(EXIT_FAILURE);
    }

    printf("{\"elf_insts\": %d, \"tot_inst\": %d}\n", elf_insts, tot_insts);
}

int main(int argc, char *const argv[]) {
    int opt;
    int enable_memchecks = 0;
    const char *elf_path = NULL;

    while ((opt = getopt(argc, argv, "me:")) != -1) {
        switch (opt) {
            case 'm':
                enable_memchecks = 1;
                break;
            case 'e':
                if (elf_path != NULL) {
                    fprintf(stderr, "-e option already passed to the program !\n");
                    usage(argv[0]);
                    return EXIT_FAILURE;
                }
                elf_path = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (elf_path == NULL) {
        fprintf(stderr, "-e option is missing\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    entry_point(elf_path, enable_memchecks);
    return EXIT_SUCCESS;
}
