//
// Created by thomas on 25/09/19.
//

#include <stdint.h>
#include <stdlib.h>
#include "memory_manager.h"

int add_allowed_mem(hash_mem_t *hashap, uintptr_t ptr, size_t size, bpf_meminfo_t *memtype);

int add_allowed_mem(hash_mem_t *hashap, uintptr_t ptr, size_t size, bpf_meminfo_t *memtype) {

    if(hashmap_put(hashap, ptr, *memtype) != 0) return -1;
    return 0;
}