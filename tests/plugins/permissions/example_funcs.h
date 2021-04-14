//
// Created by thomas on 17/03/21.
//

#ifndef UBPF_TOOLS_EXAMPLE_FUNCS_H
#define UBPF_TOOLS_EXAMPLE_FUNCS_H

#include <stdint.h>

extern uint64_t perm_none(void);

extern uint64_t perm_usr_ptr(void);

extern uint64_t perm_read(void);

extern uint64_t perm_write(void);

extern uint64_t perm_usr_ptr_read(void);

extern uint64_t perm_usr_ptr_write(void);

extern uint64_t perm_read_write(void);

extern uint64_t perm_all(void);

#endif //UBPF_TOOLS_EXAMPLE_FUNCS_H
