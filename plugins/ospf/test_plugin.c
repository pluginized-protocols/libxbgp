#include "../include/bytecode_public.h"

/*
 * ~~ Simple eBPF program ~~
 * Dummy plugin to test if
 * plugin injection works.
 * If yes, should print the
 * message on stderr.
 */
uint64_t my_super_complicated_function(args_t *args) {

    /* avoid clang warning (unused arg) */
    ebpf_print("Hello word, this is my argument %p\n", LOG_PTR(args));

    return EXIT_SUCCESS;
}
