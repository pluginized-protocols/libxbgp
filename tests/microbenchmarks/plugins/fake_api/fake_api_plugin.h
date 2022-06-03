//
// Created by thomas on 14/04/22.
//

#ifndef LIBXBGP_VM_FAKE_API_PLUGIN_H
#define LIBXBGP_VM_FAKE_API_PLUGIN_H

#include <stddef.h>

extern void *fake_alloc(size_t size);

extern int *get_memory(void);

extern int set_memory(int value);

#endif //LIBXBGP_VM_FAKE_API_PLUGIN_H
