//
// Created by thomas on 17/03/21.
//
#include <CUnit/Util.h>
#include "permissions_test.h"
#include <ubpf_public.h>
#include "plugins_manager.h"


char plugin_dir[PATH_MAX - NAME_MAX];


uint64_t perm_none(void);

uint64_t perm_usr_ptr(void);

uint64_t perm_read(void);

uint64_t perm_write(void);

uint64_t perm_usr_ptr_read(void);

uint64_t perm_usr_ptr_write(void);

uint64_t perm_read_write(void);

uint64_t perm_all(void);


static proto_ext_fun_t funcs[] = {
        {.fn = perm_none, .name= "perm_none", .attributes=HELPER_ATTR_NONE},
        {.fn = perm_usr_ptr, .name= "perm_usr_ptr", .attributes=HELPER_ATTR_USR_PTR},
        {.fn = perm_read, .name= "perm_read", .attributes=HELPER_ATTR_READ},
        {.fn = perm_write, .name= "perm_write", .attributes=HELPER_ATTR_WRITE},
        {.fn = perm_usr_ptr_read, .name= "perm_usr_ptr_read", .attributes=HELPER_ATTR_USR_PTR | HELPER_ATTR_READ},
        {.fn = perm_usr_ptr_write, .name= "perm_usr_ptr_write", .attributes=HELPER_ATTR_USR_PTR | HELPER_ATTR_WRITE},
        {.fn = perm_read_write, .name= "perm_read_write", .attributes=HELPER_ATTR_READ | HELPER_ATTR_WRITE},
        {.fn = perm_all, .name= "perm_all", .attributes=HELPER_ATTR_USR_PTR | HELPER_ATTR_READ | HELPER_ATTR_WRITE},
        proto_ext_func_null
};

static insertion_point_info_t insertions_point[] = {
        {.insertion_point_str = "default_point", .insertion_point_id = 1},
        insertion_point_info_null
};


uint64_t perm_none() {
    return 0;
}

uint64_t perm_usr_ptr() {
    return 0;
}

uint64_t perm_read() {
    return 0;
}

uint64_t perm_write() {
    return 0;
}

uint64_t perm_usr_ptr_read() {
    return 0;
}

uint64_t perm_usr_ptr_write() {
    return 0;
}

uint64_t perm_read_write() {
    return 0;
}

uint64_t perm_all() {
    return 0;
}


static int setup(void) {
    return init_plugin_manager(funcs, ".", insertions_point, 0, NULL);
}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}


static void permissions_test(void) {
    char path[PATH_MAX];
    int status;

    struct {
        const char *name;
        int should_fail;
        int perms;
    } michel[] = {
            {.name = "plugin_no_perms_ok.o", .should_fail = 0, .perms = HELPER_ATTR_NONE},
            {.name = "plugin_no_perms_ko.o", .should_fail = 1, .perms = HELPER_ATTR_NONE},
            {.name = "plugin_perm_usr_ptr_ok.o", .should_fail = 0, .perms = HELPER_ATTR_USR_PTR},
            {.name = "plugin_perm_usr_ptr_ko.o", .should_fail = 1, .perms = HELPER_ATTR_USR_PTR},
            {.name = "plugin_perm_read_ok.o", .should_fail = 0, .perms = HELPER_ATTR_READ},
            {.name = "plugin_perm_read_ko.o", .should_fail = 1, .perms = HELPER_ATTR_READ},
            {.name = "plugin_perm_write_ok.o", .should_fail = 0, .perms = HELPER_ATTR_WRITE},
            {.name = "plugin_perm_write_ko.o", .should_fail = 1, .perms = HELPER_ATTR_WRITE},
            {.name = "plugin_perm_usr_ptr_read_ok.o", .should_fail = 0, .perms = HELPER_ATTR_USR_PTR |
                                                                                 HELPER_ATTR_READ},
            {.name = "plugin_perm_usr_ptr_read_ko.o", .should_fail = 1, .perms = HELPER_ATTR_USR_PTR |
                                                                                 HELPER_ATTR_READ},
            {.name = "plugin_perm_usr_ptr_write_ok.o", .should_fail = 0, .perms = HELPER_ATTR_USR_PTR |
                                                                                  HELPER_ATTR_WRITE},
            {.name = "plugin_perm_usr_ptr_write_ko.o", .should_fail = 1, .perms = HELPER_ATTR_USR_PTR |
                                                                                  HELPER_ATTR_WRITE},
            {.name = "plugin_perm_read_write_ok.o", .should_fail = 0, .perms = HELPER_ATTR_READ | HELPER_ATTR_WRITE},
            {.name = "plugin_perm_read_write_ko.o", .should_fail = 1, .perms = HELPER_ATTR_READ | HELPER_ATTR_WRITE},
            {.name = "plugin_perm_all.o", .should_fail = 0, .perms = HELPER_ATTR_MASK},
    };

    for (size_t i = 0; i < sizeof(michel) / sizeof(michel[0]); i++) {
        memset(path, 0, sizeof(path));
        snprintf(path, sizeof(path), "%s/permissions/%s", plugin_dir, michel[i].name);

        /* test load */
        status = add_extension_code("perm_test", 14, 8,
                                    0, 1, "default_point", 13,
                                    BPF_REPLACE, 0, 0, path, 0,
                                    "super_test", 10, funcs, michel[i].perms, 1);


        CU_ASSERT_EQUAL(status, michel[i].should_fail ? -1 : 0);

        if ((michel[i].should_fail ? -1 : 0) != status) {
            fprintf(stdout, "Failed for %s\n", michel[i].name);
        }

        CU_ASSERT_EQUAL(remove_plugin("perm_test"), 0);
    }


}

CU_ErrorCode test_permissions_plugins(const char *plugin_folder) {
    CU_pSuite pSuite = NULL;
    memset(plugin_dir, 0, sizeof(plugin_dir));
    realpath(plugin_folder, plugin_dir);


    pSuite = CU_add_suite("ubpf_manager_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }


    if ((NULL == CU_add_test(pSuite, "Permission strategies", permissions_test))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}