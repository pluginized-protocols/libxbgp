//
// Created by thomas on 25/09/19.
//

#ifndef FRR_UBPF_MEMORY_MANAGER_H
#define FRR_UBPF_MEMORY_MANAGER_H


#include "hashmap.h"

#define READ_ACCESS 0100
#define WRITE_ACCESSS 0010

typedef enum BPF_MEM_TYPE {

    VM_READ = READ_ACCESS,
    VM_WRITE = WRITE_ACCESSS,
} bpf_memtype_t;

typedef struct mem_info {
    bpf_memtype_t type;
    size_t size;
} bpf_meminfo_t;

typedef hashmap_t(struct mem_info) hash_mem_t ;

#endif //FRR_UBPF_MEMORY_MANAGER_H
