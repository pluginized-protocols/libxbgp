//
// Created by thomas on 1/07/20.
//

#ifndef UBPF_TOOLS_STATIC_INJECTION_H
#define UBPF_TOOLS_STATIC_INJECTION_H

#include <include/ebpf_mod_struct.h>
#include "insertion_point.h"

int str_to_id_insertion_point(insertion_point_info_t *info, const char *str, size_t len);

int str_anchor_to_enum(const char *anchor_str, anchor_t *anchor);

int load_extension_code(const char *path, const char *extension_code_dir, proto_ext_fun_t *api_proto,
                        insertion_point_info_t *points_info);

#endif //UBPF_TOOLS_STATIC_INJECTION_H
