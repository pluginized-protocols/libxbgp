#include <ubpf_tools/include/public_bpf.h>

/*
 * ~~ Simple eBPF program ~~
 * Dummy plugin to test if
 * plugin injection works.
 * If yes, should print the
 * message on stderr.
 */
uint64_t my_super_complicated_function(bpf_full_args_t *args) {

    /* avoid clang warning (unused arg) */
    ebpf_print("Hello word, this is my argument %p\n", args);

    return EXIT_SUCCESS;
}
