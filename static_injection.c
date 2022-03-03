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
#include <regex.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>


#define get_j_obj(_1, _2, NAME, ...) NAME

#define j_obj1(identifier) \
    json_object *identifier##_jobj

#define j_obj2(type, identifier) \
    j_obj1(identifier);    \
    type identifier

#define j_obj(...) get_j_obj(__VA_ARGS__, j_obj2, j_obj1)(__VA_ARGS__)
#define j_obj_json(identifier) identifier##_jobj
#define j_obj_val(identifier) identifier
#define j_obj_get_ex(obj, identifier) json_object_object_get_ex(obj, #identifier, &j_obj_json(identifier))

struct perms valid_perms[] = {
        {.perm_str = "none", .perm = HELPER_ATTR_NONE, .len_perm = 4},
        {.perm_str = "usr_ptr", .perm = HELPER_ATTR_USR_PTR, .len_perm = 7},
        {.perm_str = "read", .perm = HELPER_ATTR_READ, .len_perm = 4},
        {.perm_str = "write", .perm = HELPER_ATTR_WRITE, .len_perm = 5},
        valid_perm_null
};

#define reserved_insertion_point_null {.name = NULL, .id = 0}

enum RESERVED_ID_INSERTION {
    JOB_PLUGINS_INSERTION = 0,
};

static struct reserved_insertion_point {
    const char *name;
    size_t name_len;
    int id;
} reserved_insertion_point[] = {
        [JOB_PLUGINS_INSERTION] = {.name = "job_plugins", .name_len = 12, .id = INSERTION_POINT_ID_RESERVED},
        reserved_insertion_point_null // null marker
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

    // check for reserved insertion points
    for (i = 0; reserved_insertion_point->name != NULL && reserved_insertion_point->id != 0; i++) {
        if (strncmp(str, reserved_insertion_point[i].name, len) == 0) {
            return reserved_insertion_point[i].id;
        }
    }
    return -1;
}

static inline int fill_info_job_plugins(const char *plugin_name,
                                        size_t plugin_name_len,
                                        struct insertion_point_parser *p_parser) {
    static int job_seq = 0;
    assert(p_parser != NULL);

    *p_parser = (typeof(*p_parser)) {
            .name_insertion = reserved_insertion_point[JOB_PLUGINS_INSERTION].name,
            .name_insertion_len = reserved_insertion_point[JOB_PLUGINS_INSERTION].name_len,
            .insertion_point_id = reserved_insertion_point[JOB_PLUGINS_INSERTION].id,
            .anchor = BPF_REPLACE,
            .seq = job_seq,
            .pluglet_name= plugin_name,
            .pluglet_name_len = plugin_name_len,

            .next = NULL,
            .prev = NULL
    };

    job_seq += 10;
    return 0;
}

static int join_path(const char *in1, const char *in2, char *out, size_t out_len) {
    size_t final_len;
    size_t sprint_len;
    char tmp_buf[PATH_MAX];
    memset(tmp_buf, 0, PATH_MAX);
    memset(out, 0, out_len);

    sprint_len = snprintf(tmp_buf, PATH_MAX, "%s/%s", in1, in2);

    if (sprint_len >= PATH_MAX) {
        fprintf(stderr, "Name is too long!\n");
        return -1;
    }
    tmp_buf[sprint_len] = 0;

    if (!realpath(tmp_buf, out)) return -1;

    assert(out_len <= PATH_MAX);
    if ((final_len = strnlen(out, PATH_MAX)) >= out_len) return -1;
    return final_len;
}

static inline int absolute_path(const char *in) {
    return in[0] == '/';
}

static inline int get_real_path(const char *base_dir, const char *decoded_path, char *out, size_t out_len) {
    char tmp_path[PATH_MAX];
    const char *working_path;

    assert(out_len >= PATH_MAX);

    if (!absolute_path(decoded_path)) {
        if (join_path(base_dir, decoded_path, tmp_path, sizeof(tmp_path)) < 0) {
            fprintf(stderr, "Join path too long!\n");
            return -1;
        }
        working_path = tmp_path;
    } else {
        working_path = decoded_path;
    }

    if (realpath(working_path, out) == NULL) {
        perror("real_path resolution failed");
        return -1;
    }

    return 0;
}

#define free_list(list) do {        \
    struct insertion_point_parser *elt, *tmp;           \
    DL_FOREACH_SAFE(list,elt,tmp) { \
        DL_DELETE(list,elt);        \
        free(elt);                  \
    }                               \
} while(0)

#define free_hash(hash) do { \
    struct obj_code_list_parser *elt, *tmp; \
    HASH_ITER(hh, hash, elt, tmp) {         \
        HASH_DEL(hash, elt); \
        free(elt);\
    }\
} while(0)

static int iter_anchors(json_object *insertion_point,
                        const char *insertion_point_name,
                        size_t insertion_point_name_len,
                        insertion_point_info_t *points_info,
                        struct insertion_point_parser **p_parser) {
    j_obj(const char *, anchor);
    anchor_t num_anchor;
    j_obj(const char *, seq);

    int point_id;

    struct insertion_point_parser *new_pluglet;

    /* iterators */
    struct json_object_iterator anchor_it;
    struct json_object_iterator anchor_it_end;
    struct json_object_iterator seq_it;
    struct json_object_iterator seq_it_end;


    const char *current_vm_name;
    int current_vm_name_len;
    long parsed_seq;
    char *chk_ptr;

    anchor_it_end = json_object_iter_end(insertion_point);
    for (anchor_it = json_object_iter_begin(insertion_point);
         !json_object_iter_equal(&anchor_it, &anchor_it_end);
         json_object_iter_next(&anchor_it)) {

        j_obj_json(anchor) = json_object_iter_peek_value(&anchor_it);
        j_obj_val(anchor) = json_object_iter_peek_name(&anchor_it);

        seq_it_end = json_object_iter_end(j_obj_json(anchor));

        for (seq_it = json_object_iter_begin(j_obj_json(anchor));
             !json_object_iter_equal(&seq_it, &seq_it_end);
             json_object_iter_next(&seq_it)) {

            /* create new node in insertion_point_parser list */
            new_pluglet = malloc(sizeof(*new_pluglet));
            if (!new_pluglet) return -1;

            j_obj_json(seq) = json_object_iter_peek_value(&seq_it);
            j_obj_val(seq) = json_object_iter_peek_name(&seq_it);

            current_vm_name = json_object_get_string(j_obj_json(seq));
            current_vm_name_len = json_object_get_string_len(j_obj_json(seq));


            if (str_anchor_to_enum(j_obj_val(anchor), &num_anchor) != 0) {
                fprintf(stderr, "Unknown anchor \"%s\" ?\n", j_obj_val(anchor));
                return -1;
            }
            parsed_seq = strtol(j_obj_val(seq), &chk_ptr, 10);
            if (*chk_ptr != 0) {
                fprintf(stderr, "The sequence is not a number (%s) !\n", j_obj_val(seq));
                return -1;
            }
            if (parsed_seq >= INT32_MAX) {
                fprintf(stderr, "Sequence overflow %ld > %d\n", parsed_seq, INT32_MAX);
                return -1;
            }

            point_id = str_to_id_insertion_point(points_info,
                                                 insertion_point_name,
                                                 insertion_point_name_len);
            if (point_id == -1) {
                fprintf(stderr, "Unknown insertion point \"%s\"!\n", insertion_point_name);
                return -1;
            }

            *new_pluglet = (struct insertion_point_parser) {
                    .anchor = num_anchor,
                    .seq = (int) parsed_seq,
                    .name_insertion = insertion_point_name,
                    .name_insertion_len = insertion_point_name_len,
                    .insertion_point_id = point_id,
                    .pluglet_name = current_vm_name,
                    .pluglet_name_len = current_vm_name_len
            };

            DL_APPEND(*p_parser, new_pluglet);
        }
    }
    return 0;
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
    size_t len;
    unsigned int i, j;
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

static int job_plugin_parser(json_object *obj_job,
                      struct obj_code_list_parser *obj_info,
                      struct job_plugin_parser *j_parser) {

    // since this is a job plugin, we need to add
    // all pluglets referenced to obj_obj_info in
    // a structure insertion_point_parser.
    struct obj_code_list_parser *curr_obj, *obj_tmp;

    j_obj(unsigned long long int, schedule);

    if (!j_parser) return -1;
    if (!j_obj_get_ex(obj_job, schedule)) {
        fprintf(stderr, "\"schedule\" field missing! A job plugin must have a schedule!\n");
        return -1;
    }

    j_obj_val(schedule) = json_object_get_uint64(j_obj_json(schedule));

    HASH_ITER(hh, obj_info, curr_obj, obj_tmp) {
        struct insertion_point_parser *new_insert_parser;
        new_insert_parser = malloc(sizeof(*new_insert_parser));
        if (!new_insert_parser) {
            fprintf(stderr, "Unable to allocate memory\n");
            return -1;
        }
        fill_info_job_plugins(obj_info->name, obj_info->name_len, new_insert_parser);
        DL_APPEND(j_parser->parser, new_insert_parser);
    }


    j_parser->schedule = schedule;

    return 0;
}

/* p_parser will be dynamically allocated inside this function !
 * Must be freed when not needed anymore */
static int insertion_points_parser(insertion_point_info_t *point_info,
                            json_object *insertion_points,
                            struct insertion_point_parser **p_parser) {
    struct json_object_iterator curr_insertion_point_iter;
    struct json_object_iterator j_iter_end;
    const char *insertion_point_name;

    j_obj(insertion_point);

    assert(*p_parser == NULL);

    j_iter_end = json_object_iter_end(insertion_points);

    for (curr_insertion_point_iter = json_object_iter_begin(insertion_points);
         !json_object_iter_equal(&curr_insertion_point_iter, &j_iter_end);
         json_object_iter_next(&curr_insertion_point_iter)) {
        j_obj_json(insertion_point) = json_object_iter_peek_value(&curr_insertion_point_iter);
        insertion_point_name = json_object_iter_peek_name(&curr_insertion_point_iter);


        if (iter_anchors(j_obj_json(insertion_point), insertion_point_name,
                         strnlen(insertion_point_name, 50),
                         point_info, p_parser) == -1) {
            return -1;
        }
    }

    return 0;
}

static int obj_code_list_parser(json_object *obj_code_list, struct obj_code_list_parser **o_parser,
                         const char *base_dir, int default_jit) {
    assert(*o_parser == NULL);

    struct json_object_iterator obj_iter;
    struct json_object_iterator obj_iter_end;

    struct obj_code_list_parser *curr_code;
    j_obj(obj_code);
    const char *name_code;
    size_t name_code_len;

    j_obj(jit);
    j_obj(const char *, obj);
    int path_code_len;
    j_obj(permissions);
    j_obj(add_memcheck);
    j_obj(const char *, memory_mgmt);
    mem_type_t mt;

    obj_iter_end = json_object_iter_end(obj_code_list);

    for (obj_iter = json_object_iter_begin(obj_code_list);
         !json_object_iter_equal(&obj_iter, &obj_iter_end);
         json_object_iter_next(&obj_iter)) {

        name_code = json_object_iter_peek_name(&obj_iter);
        name_code_len = strnlen(name_code, NAME_MAX);

        j_obj_json(obj_code) = json_object_iter_peek_value(&obj_iter);

        curr_code = malloc(sizeof(*curr_code) + name_code_len + 1);
        if (!curr_code) return -1;

        strncpy(curr_code->name, name_code, name_code_len);
        curr_code->name[name_code_len] = 0;
        curr_code->name_len = name_code_len;

        HASH_ADD(hh, *o_parser, name, name_code_len, curr_code);

        if (j_obj_get_ex(j_obj_json(obj_code), permissions)) {
            curr_code->permissions = parse_permissions_pluglet(j_obj_json(permissions));
        } else {
            curr_code->permissions = 0;
        }

        if (j_obj_get_ex(j_obj_json(obj_code), memory_mgmt)) {
            j_obj_val(memory_mgmt) = json_object_get_string(j_obj_json(memory_mgmt));
            mt = str_memtype_to_enum(j_obj_val(memory_mgmt));
            if (mt == MIN_MEM) {
                fprintf(stderr, "Unknown memory manager: \"%s\" !\n", j_obj_val(memory_mgmt));
                return -1;
            }
            curr_code->memory_mgt = mt;
        } else {
            curr_code->memory_mgt = BUMP_MEM;
        }

        if (!j_obj_get_ex(j_obj_json(obj_code), obj)) {
            fprintf(stderr, "\"obj\" field missing. Must give the file name of the pluglet!\n");
            return -1;
        } else {
            j_obj_val(obj) = json_object_get_string(j_obj_json(obj));
            path_code_len = join_path(base_dir, j_obj_val(obj),
                                      curr_code->path_code,
                                      sizeof(curr_code->path_code));
            if (path_code_len == -1) {
                fprintf(stderr, "Internal error, not enough space to represent the full pluglet path\n");
                return -1;
            }
            curr_code->path_len = path_code_len;
        }

        if (j_obj_get_ex(j_obj_json(obj_code), add_memcheck)) {
            curr_code->add_memchecks = json_object_get_boolean(j_obj_json(add_memcheck));
        } else {
            curr_code->add_memchecks = 0;
        }

        if (j_obj_get_ex(j_obj_json(obj_code), jit)) {
            curr_code->jit = json_object_get_boolean(j_obj_json(jit));
        } else {
            curr_code->jit = default_jit;
        }
    }

    return 0;
}

static int global_opts_parser(json_object *main_json, struct global_opts_parser *g_parser,
                       const char *default_base_dir, size_t base_dir_len) {
    assert(g_parser != NULL);
    assert(main_json != NULL);

    /* how much memory should be given to the plugin (in bytes) */
    uint64_t tmp_mem_val;
    j_obj(extra_mem);
    j_obj(shared_mem);
    /* all pluglet should be transpiled to x86 ? */
    j_obj(jit_all);
    /* override default pluglet dir */
    j_obj(const char *, obj_dir);
    size_t obj_dir_len;
    /* plugin name */
    j_obj(const char *, name);
    size_t name_len;

    /* 1. Parse JIT value */
    if (j_obj_get_ex(main_json, jit_all)) {
        g_parser->jit_all = json_object_get_boolean(j_obj_json(jit_all));
    } else {
        g_parser->jit_all = 0;
    }

    /* 2. Parse obj dir */
    if (j_obj_get_ex(main_json, obj_dir)) {
        obj_dir_len = json_object_get_string_len(j_obj_json(obj_dir));
        j_obj_val(obj_dir) = json_object_get_string(j_obj_json(obj_dir));
        if (obj_dir_len > sizeof(g_parser->pluglet_dir) - 1) {
            fprintf(stderr, "\"obj_dir\" path is too long %zu > %lu\n",
                    obj_dir_len, sizeof(g_parser->pluglet_dir));
            return -1;
        }
        strncpy(g_parser->pluglet_dir, j_obj_val(obj_dir), obj_dir_len);
        g_parser->pluglet_dir[obj_dir_len] = 0;
    } else {
        strncpy(g_parser->pluglet_dir, default_base_dir, base_dir_len);
        g_parser->pluglet_dir[base_dir_len] = 0;
    }

    /* 3. Parse name plugin */
    if (j_obj_get_ex(main_json, name)) {
        name_len = json_object_get_string_len(j_obj_json(name));
        j_obj_val(name) = json_object_get_string(j_obj_json(name));
        if (name_len > sizeof(g_parser->plugin_name) - 1) {
            fprintf(stderr, "\"name\" length is too long %zu > %lu\n",
                    name_len, sizeof(g_parser->plugin_name));
            return -1;
        }
        strncpy(g_parser->plugin_name, j_obj_val(name), name_len);
        g_parser->plugin_name[name_len] = 0;
        g_parser->plugin_name_len = name_len;
    } else {
        fprintf(stderr, "\"name\" field missing! Please add a name for the plugin\n");
        return -1;
    }

    /* 4. shared mem */
    if (j_obj_get_ex(main_json, shared_mem)) {
        tmp_mem_val = json_object_get_uint64(j_obj_json(shared_mem));
        if (tmp_mem_val > MAX_MEM_PARSE) {
            fprintf(stderr, "Woah ! Attempting to allocate too "
                            "much memory %lu > %d\n", tmp_mem_val, MAX_MEM_PARSE);
            return -1;
        }
        g_parser->shared_mem = (int) tmp_mem_val;
    } else {
        // by default no bytes are allocated
        g_parser->shared_mem = 0;
    }

    /* 5. extra mem */
    if (j_obj_get_ex(main_json, extra_mem)) {
        tmp_mem_val = json_object_get_uint64(j_obj_json(extra_mem));
        if (tmp_mem_val > MAX_MEM_PARSE) {
            fprintf(stderr, "Woah ! Attempting to allocate too "
                            "much memory %lu > %d\n", tmp_mem_val, MAX_MEM_PARSE);
            return -1;
        }
        g_parser->extra_mem = (int) tmp_mem_val;
    } else {
        // 4096 extra memory bytes will be allocated to the pluglets of the plugin
        g_parser->extra_mem = 4096;
    }

    return 0;
}

static int load_pluglet(const char *path, const char *extension_code_dir,
                 proto_ext_fun_t *api_proto, insertion_point_info_t *points_info) {
    int ret_val = -1;
    int is_job_plugin = 0;
    json_object *main_obj = json_object_from_file(path);

    j_obj(obj_code_list);
    j_obj(insertion_points);
    j_obj(job_plugin);

    struct plugin *plugin;

    struct insertion_point_parser *insertion_points_list = NULL;
    struct insertion_point_parser *curr_iter = NULL;
    struct job_plugin_parser job_plugin_info = {0};
    struct obj_code_list_parser *o_parser = NULL;
    struct global_opts_parser g_parser;

    if (!main_obj) {
        fprintf(stderr, "Error while reading %s: %s\n", path, json_util_get_last_err());
        goto end;
    }

    /* first parse global options related to the plugin */
    if (global_opts_parser(main_obj, &g_parser, extension_code_dir, strnlen(extension_code_dir, PATH_MAX)) != 0) {
        fprintf(stderr, "There were errors while parsing global plugin info\n");
        goto end;
    }

    /* parse obj_code_list before job and insertion point. Since they may require info from this */
    if (j_obj_get_ex(main_obj, obj_code_list)) {
        if (obj_code_list_parser(j_obj_json(obj_code_list), &o_parser,
                                 g_parser.pluglet_dir, g_parser.jit_all) != 0) {
            goto end;
        }
    } else {
        fprintf(stderr, "Missing \"obj_code_list\" field, which is required to load plugin\n");
        goto end;
    }

    /* get json object related to the insertion point/job_plugin */
    if (!j_obj_get_ex(main_obj, insertion_points)) {
        j_obj_json(insertion_points) = NULL;
    }
    if (!j_obj_get_ex(main_obj, job_plugin)) {
        j_obj_json(job_plugin) = NULL;
    }

    if (j_obj_json(job_plugin) == NULL && j_obj_json(insertion_points) == NULL) {
        fprintf(stderr, "Missing \"inserstion_points\" or \"job_plugin\" field!\n"
                        "At least one is required to inject the plugin !\n");
        goto end;
    }

    /* parse job plugin */
    if (j_obj_json(job_plugin)) {
        is_job_plugin = 1;
        if (job_plugin_parser(j_obj_json(job_plugin), o_parser,
                              &job_plugin_info) == -1) {
            goto end;
        }
        insertion_points_list = job_plugin_info.parser;
    }

    /* parse insertion point section if any */
    if (j_obj_json(insertion_points)) {
        if (is_job_plugin) {
            // clash
            fprintf(stderr, "The plugin cannot be a job plugin and a insertion point plugin\n");
            goto end;
        }

        if (insertion_points_parser(points_info,
                                    j_obj_json(insertion_points), &insertion_points_list) == -1) {
            goto end;
        }
    }

    struct obj_code_list_parser *obj_code_info;
    /* time to add the plugin to the manager ! */
    DL_FOREACH(insertion_points_list, curr_iter) {

        /* find pluglet info related to the name */
        HASH_FIND(hh, o_parser, curr_iter->pluglet_name, curr_iter->pluglet_name_len, obj_code_info);
        if (obj_code_info == NULL) {
            fprintf(stderr, "Pluglet \"%s\" not found", curr_iter->pluglet_name);
            goto end;
        }

        if (add_extension_code(g_parser.plugin_name, g_parser.plugin_name_len, g_parser.extra_mem,
                               g_parser.shared_mem, curr_iter->insertion_point_id, curr_iter->name_insertion,
                               curr_iter->name_insertion_len, curr_iter->anchor, curr_iter->seq,
                               obj_code_info->jit, obj_code_info->path_code, 0, curr_iter->pluglet_name,
                               curr_iter->pluglet_name_len, api_proto, obj_code_info->permissions,
                               obj_code_info->add_memchecks, obj_code_info->memory_mgt) != 0) {
            goto end;
        }

    }

    if (is_job_plugin) {
        plugin = plugin_by_name(g_parser.plugin_name);
        if (!plugin) {
            fprintf(stderr, "Oh no! Plugin not found !\n");
            goto end;
        }

        if (add_plugin_job(plugin, INSERTION_POINT_ID_RESERVED, job_plugin_info.schedule) == -1) {
            fprintf(stderr, "Failed to add job !\n");
            goto end;
        }
    }

    /* everything is okay from here */
    ret_val = 0;

    end:
    if (insertion_points_list) free_list(insertion_points_list);
    if (o_parser) free_hash(o_parser);
    if (main_obj) json_object_put(main_obj);
    return ret_val;
}


static char *str_strip(char *s, size_t max_len) {
    char *end;
    size_t len;

    len = strnlen(s, max_len);
    if (len == max_len) return NULL;

    end = s + len - 1;
    while (end >= s && isspace(*end)) {
        end--;
    }

    *(end + 1) = '\0';

    while (*s && isspace(*s)) {
        s++;
    }

    return s;
}

#define match_len(regmatch) ((regmatch)->rm_eo - (regmatch)->rm_so)

int load_extension_code(const char *path, const char *extension_code_dir,
                        proto_ext_fun_t *api_proto, insertion_point_info_t *points_info) {
    int ret_val = -1;
    FILE *meta_manifest = NULL;
    char line[8192];
    char plugin_dir[PATH_MAX];
    char real_plugin_dir[PATH_MAX];
    char mate_manifest_base_dir[PATH_MAX];
    const char *base_dir_meta_manifest;
    size_t regmatch_len;
    char *stripped_line;
    int value;
    regex_t regex_;
    regex_t *regex = NULL;
    static const char *str_regex = "^include\\s+((\\.{1,2}\\/|[a-zA-Z0-9_\\/\\-\\\\])*\\.[a-zA-Z0-9]+)$";

    regmatch_t regmatch[2];
    size_t nmatch = sizeof(regmatch) / sizeof(regmatch[0]);

    if (regcomp(&regex_, str_regex, REG_EXTENDED) != 0) {
        fprintf(stderr, "Unable to compile regex\n");
        goto end;
    } else {
        regex = &regex_;
    }

    meta_manifest = fopen(path, "r");
    if (!meta_manifest) {
        fprintf(stderr, "Error while opening %s: %s", path, strerror(errno));
        goto end;
    }

    strncpy(mate_manifest_base_dir, path, PATH_MAX);
    base_dir_meta_manifest = dirname(mate_manifest_base_dir);

    while (fgets(line, sizeof(line), meta_manifest)) {
        if ((stripped_line = str_strip(line, sizeof(line))) == NULL) {
            fprintf(stderr, "Unable to parse \"%s\"\n", line);
            goto end;
        }

        if (*stripped_line != 0) {
            value = regexec(regex, stripped_line, nmatch, regmatch, 0);
            if (value == 0) { /* value found */
                regmatch_len = match_len(&regmatch[1]);
                if (regmatch_len > sizeof(plugin_dir)) {
                    fprintf(stderr, "File directory too long %zu > %lu\n", regmatch_len, sizeof(plugin_dir));
                    goto end;
                }


                strncpy(plugin_dir, stripped_line + regmatch[1].rm_so, regmatch_len);
                plugin_dir[regmatch_len] = 0;
                if (get_real_path(base_dir_meta_manifest, plugin_dir, real_plugin_dir, sizeof(real_plugin_dir)) != 0) {
                    fprintf(stderr, "Unable to resolve plugin manifest path\n");
                    goto end;
                }

                if (load_pluglet(real_plugin_dir, extension_code_dir, api_proto, points_info) != 0) {
                    fprintf(stderr, "Unable to load \"%s\"\n", plugin_dir);
                    goto end;
                }
                // TODO check about sequence number insertion point (when multiple plugins are loaded at once)

            }
        }
    }

    /* if this is reached, everything went well */
    ret_val = 0;

    end:
    if (meta_manifest) fclose(meta_manifest);
    if (regex) regfree(regex);
    return ret_val;
}