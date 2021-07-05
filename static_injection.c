//
// Created by thomas on 1/07/20.
//

#include "static_injection.h"
#include "insertion_point.h"
#include "plugins_manager.h"
#include "evt_plugins.h"

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include <stddef.h>

struct insertion_json {
    size_t name_insertion_len;
    const char *name_insertion;
    int id_insertion;
    anchor_t anchor;
    int seq;
};

struct job_plugin_info {
    uint64_t schedule;
};

struct perms valid_perms[] = {
        {.perm_str = "none", .perm = HELPER_ATTR_NONE, .len_perm = 4},
        {.perm_str = "usr_ptr", .perm = HELPER_ATTR_USR_PTR, .len_perm = 7},
        {.perm_str = "read", .perm = HELPER_ATTR_READ, .len_perm = 4},
        {.perm_str = "write", .perm = HELPER_ATTR_WRITE, .len_perm = 5},
        valid_perm_null
};

int str_anchor_to_enum(const char *anchor_str, anchor_t *anchor) {
    anchor_t anchor_;
    anchor_ = strncmp("replace", anchor_str, 7) == 0 ? BPF_REPLACE :
              strncmp("post", anchor_str, 4) == 0 ? BPF_POST :
              strncmp("pre", anchor_str, 3) == 0 ? BPF_PRE : BPF_UNKNOWN;

    if (anchor_ == BPF_UNKNOWN) return -1;
    *anchor = anchor_;
    return 0;
}

int str_to_id_insertion_point(insertion_point_info_t *info, const char *str, size_t len) {
    int i;
    for (i = 0; !is_insertion_point_info_null(info + i); i++) {
        if (strncmp(str, info[i].insertion_point_str, len) == 0) {
            return info[i].insertion_point_id;
        }
    }
    return -1;
}

static inline void fill_info_job_plugins(struct insertion_json *info) {
    static int job_seq = 0;

    info->name_insertion = "job_plugins";
    info->name_insertion_len = 11;
    info->anchor = BPF_REPLACE;
    info->seq = job_seq;

    job_seq += 10;
}

static int join_path(const char *in1, const char *in2, char *out, size_t out_len) {
    size_t final_len;
    char tmp_buf[PATH_MAX];
    memset(tmp_buf, 0, PATH_MAX);
    memset(out, 0, out_len);

    snprintf(tmp_buf, PATH_MAX, "%s/%s", in1, in2);
    if (!realpath(tmp_buf, out)) return -1;

    assert(out_len <= PATH_MAX);
    if ((final_len = strnlen(out, PATH_MAX)) >= out_len) return -1;
    return final_len;
}

static int iter_anchors(json_object *insertion_point, const char *vm_name, struct insertion_json *info) {
    struct json_object_iterator anchor_it;
    struct json_object_iterator anchor_it_end;
    struct json_object_iterator seq_it;
    struct json_object_iterator seq_it_end;
    json_object *anchor;
    json_object *seq;
    const char *anchor_str;
    const char *seq_str;
    const char *current_vm_name;
    int current_vm_name_len;
    long parsed_seq;
    char *chk_ptr;
    anchor_t num_anchor;

    anchor_it_end = json_object_iter_end(insertion_point);
    for (anchor_it = json_object_iter_begin(insertion_point);
         !json_object_iter_equal(&anchor_it, &anchor_it_end);
         json_object_iter_next(&anchor_it)) {

        anchor = json_object_iter_peek_value(&anchor_it);
        anchor_str = json_object_iter_peek_name(&anchor_it);

        seq_it_end = json_object_iter_end(anchor);
        for (seq_it = json_object_iter_begin(anchor);
             !json_object_iter_equal(&seq_it, &seq_it_end);
             json_object_iter_next(&seq_it)) {

            seq = json_object_iter_peek_value(&seq_it);
            seq_str = json_object_iter_peek_name(&seq_it);

            current_vm_name = json_object_get_string(seq);
            current_vm_name_len = json_object_get_string_len(seq);

            if (strncmp(vm_name, current_vm_name, current_vm_name_len) == 0) {

                if (str_anchor_to_enum(anchor_str, &num_anchor) != 0) return -1;
                parsed_seq = strtol(seq_str, &chk_ptr, 10);
                if (*chk_ptr != 0) {
                    return -1;
                }
                if (parsed_seq >= INT32_MAX) {
                    return -1;
                }

                info->anchor = num_anchor;
                info->seq = (int) parsed_seq;
                return 0;
            }
        }
    }
    return -1;
}

static int is_job_plugin_json(const char *plugin_str, json_object *manifest, struct job_plugin_info *jinfo) {
    json_object *cron_plugins;
    json_object *job_plugin;
    json_object *schedule;

    uint64_t scheduling_time;

    if (!json_object_object_get_ex(manifest, "jobs_plugins", &cron_plugins)) {
        return -1; // no cron plugin. Stop now
    }

    if (!json_object_object_get_ex(cron_plugins, plugin_str, &job_plugin)) return -1;
    if (!json_object_object_get_ex(job_plugin, "schedule", &schedule)) return -1;

    scheduling_time = json_object_get_uint64(schedule);

    jinfo->schedule = scheduling_time;
    return 0;
}

static int
get_insertion_point_for_vm(json_object *insertions_point, const char *vm_name, struct insertion_json *j_point) {
    struct json_object_iterator insertion_point;
    struct json_object_iterator insertion_point_end;

    json_object *current_insertion_point;
    const char *current_insertion_point_str;

    insertion_point_end = json_object_iter_end(insertions_point);
    for (insertion_point = json_object_iter_begin(insertions_point);
         !json_object_iter_equal(&insertion_point, &insertion_point_end);
         json_object_iter_next(&insertion_point)) {

        current_insertion_point = json_object_iter_peek_value(&insertion_point);
        current_insertion_point_str = json_object_iter_peek_name(&insertion_point);

        if (iter_anchors(current_insertion_point, vm_name, j_point) == 0) {
            j_point->name_insertion = current_insertion_point_str;
            j_point->name_insertion_len = strnlen(current_insertion_point_str, NAME_MAX);
            return 0;
        }

    }
    return -1;
}

static int to_lower(const char *src, size_t src_len, char *dst, size_t dst_len) {
    unsigned int i;
    if (dst_len < src_len) return -1;

    for (i = 0; i < src_len && src[i]; i++) {
        dst[i] = tolower(src[i]);
    }
    if (i < dst_len) dst[i] = 0;
    return 0;
}

#define MAX(A, B) (((A) > (B)) ? (A) : (B))

static int parse_permissions_pluglet(json_object *permission) {
    int len;
    int i, j;
    int final_perm;
    const char *perm;
    char lower_perm_str[16];
    size_t len_perm;
    json_object *curr_obj;
    int match = 0;

    final_perm = 0;
    len = json_object_array_length(permission);

    for (i = 0; i < len; i++) {
        curr_obj = json_object_array_get_idx(permission, i);
        if (curr_obj == NULL) return -1;

        len_perm = json_object_get_string_len(curr_obj);
        perm = json_object_get_string(curr_obj);

        if (perm == NULL) return -1;

        for (j = 0; !valid_perm_is_null(&valid_perms[j]) && !match; j++) {
            memset(lower_perm_str, 0, sizeof(lower_perm_str));
            if (to_lower(perm, len_perm, lower_perm_str, sizeof(lower_perm_str)) != 0) {
                return -1;
            }

            if (strncmp(valid_perms[j].perm_str, lower_perm_str, MAX(valid_perms[j].len_perm, len_perm)) == 0) {
                final_perm |= valid_perms[j].perm;
                match = 1;
            }
        }

        if (!match) {
            fprintf(stderr, "No permission matches \"%s\". Please change your pluglet permissions\n", perm);
            return -1;
        } else {
            // reset match for
            match = 0;
        }
    }
    return final_perm;
}


static int parse_manifest(json_object *plugins, json_object *insertion_point,
                          int default_jit, const char *obj_dir, proto_ext_fun_t *api_proto,
                          insertion_point_info_t *points_info) {
    int jit_val;
    int permissions;
    int add_memcheck_insts;

    int64_t extra_mem_val = 0;
    int64_t shared_mem_val = 0;
    const char *obj_code_str;
    int insertion_point_id;

    char obj_path[PATH_MAX];

    struct insertion_json info;

    struct json_object_iterator it_plugins;
    struct json_object_iterator it_plugins_end;

    struct json_object_iterator it_bytecode;
    struct json_object_iterator it_bytecode_end;

    struct json_object *extra_mem;
    struct json_object *shared_mem;
    struct json_object *obj_code_lst;
    struct json_object *curr_code_obj;
    struct json_object *name_obj;
    struct json_object *jit;
    struct json_object *permissions_pluglet;
    struct json_object *memcheck_add;

    const char *plugin_str;
    const char *vm_str;
    struct json_object *curr_plugin;

    struct job_plugin_info _jinfo;
    struct job_plugin_info *jinfo = NULL;
    plugin_t *plugin;

    it_plugins_end = json_object_iter_end(plugins);
    for (it_plugins = json_object_iter_begin(plugins);
         !json_object_iter_equal(&it_plugins, &it_plugins_end);
         json_object_iter_next(&it_plugins)) {

        plugin_str = json_object_iter_peek_name(&it_plugins);
        curr_plugin = json_object_iter_peek_value(&it_plugins);


        if (json_object_object_get_ex(curr_plugin, "extra_mem", &extra_mem)) {
            extra_mem_val = json_object_get_int64(extra_mem);
        }
        if (json_object_object_get_ex(curr_plugin, "shared_mem", &shared_mem)) {
            shared_mem_val = json_object_get_int64(shared_mem);
        }

        if (!json_object_object_get_ex(curr_plugin, "obj_code_list", &obj_code_lst)) {
            return -1; // no bytecode to load !?
        }

        it_bytecode_end = json_object_iter_end(obj_code_lst);
        for (it_bytecode = json_object_iter_begin(obj_code_lst);
             !json_object_iter_equal(&it_bytecode, &it_bytecode_end);
             json_object_iter_next(&it_bytecode)) {

            memset(&info, 0, sizeof(info));
            memset(obj_path, 0, sizeof(obj_path));
            jit_val = default_jit;

            curr_code_obj = json_object_iter_peek_value(&it_bytecode);
            vm_str = json_object_iter_peek_name(&it_bytecode);

            if (!json_object_object_get_ex(curr_code_obj, "obj", &name_obj)) return -1;
            obj_code_str = json_object_get_string(name_obj);

            if (join_path(obj_dir, obj_code_str, obj_path, PATH_MAX) <= 0) {
                return -1;
            }

            if (json_object_object_get_ex(curr_code_obj, "jit", &jit)) {
                jit_val = json_object_get_boolean(jit);
            }

            if (get_insertion_point_for_vm(insertion_point, vm_str, &info) != 0) {
                memset(&jinfo, 0, sizeof(_jinfo));
                jinfo = &_jinfo;

                if (is_job_plugin_json(plugin_str, plugins, jinfo) == -1) {
                    return -1;
                } else {
                    fill_info_job_plugins(&info);
                }
            }

            insertion_point_id = str_to_id_insertion_point(points_info, info.name_insertion, info.name_insertion_len);

            if (json_object_object_get_ex(curr_code_obj, "permissions", &permissions_pluglet)) {
                permissions = parse_permissions_pluglet(permissions_pluglet);
                if (permissions == -1) {
                    fprintf(stderr, "Unable to read permission of pluglet\n");
                    return -1;
                }

            } else {
                permissions = 0;
            }

            if (json_object_object_get_ex(curr_code_obj, "add_memcheck", &memcheck_add)) {
                add_memcheck_insts = json_object_get_boolean(memcheck_add);
            } else {
                add_memcheck_insts = 1; // by default, we add runtime checks
            }

            if (add_extension_code(plugin_str, strnlen(plugin_str, NAME_MAX), extra_mem_val,
                                   shared_mem_val, insertion_point_id, info.name_insertion,
                                   info.name_insertion_len, info.anchor, info.seq, jit_val, obj_path, 0, vm_str,
                                   strnlen(vm_str, NAME_MAX), api_proto, permissions, add_memcheck_insts) != 0) {
                return -1;
            }

            if (jinfo != NULL) {
                plugin = plugin_by_name(plugin_str);
                if (!plugin) {
                    fprintf(stderr, "Oh no! Plugin not found !");
                    return -1;
                }

                if (add_plugin_job(plugin, insertion_point_id, jinfo->schedule) == -1) {
                    fprintf(stderr, "Failed to add job !");
                }
            }
        }
    }
    return 0;
}

int load_extension_code(const char *path, const char *extension_code_dir, proto_ext_fun_t *api_proto,
                        insertion_point_info_t *points_info) {

    int ret_val;

    json_object *main_obj = json_object_from_file(path);

    json_object *insertion_point;
    json_object *plugins;
    json_object *jit_all;
    json_object *obj_dir;

    int jit_all_val;
    const char *obj_dir_str;

    if (!main_obj) {
        fprintf(stderr, "%s\n", json_util_get_last_err());
        return -1;
    }

    if (json_object_object_get_ex(main_obj, "jit_all", &jit_all)) {
        jit_all_val = json_object_get_boolean(jit_all);
    } else {
        jit_all_val = 0;
    }

    if (json_object_object_get_ex(main_obj, "obj_dir", &obj_dir)) {
        obj_dir_str = json_object_get_string(obj_dir);
    } else if (extension_code_dir) {
        obj_dir_str = extension_code_dir;
    } else {
        return -1;
    }

    if (!json_object_object_get_ex(main_obj, "plugins", &plugins)) return -1;
    if (!json_object_object_get_ex(main_obj, "insertion_points", &insertion_point)) return -1;

    ret_val = parse_manifest(plugins, insertion_point, jit_all_val, obj_dir_str, api_proto, points_info);
    json_object_put(main_obj);
    return ret_val;
}