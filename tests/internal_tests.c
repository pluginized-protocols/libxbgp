//
// Created by thomas on 24/03/20.
//

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>

#include <CUnit/CUnit.h>
#include <sys/mman.h>
#include <libgen.h>
#include "internal_tests.h"

#include "ubpf_api.h"


/* taken for test */

#define __NUMARGS_SPRINTF(...)  (sizeof((uintptr_t[]){__VA_ARGS__})/sizeof(uintptr_t))

#define ubpf_sprintf(str, size, format, ...)\
ebpf_bvsnprintf(NULL, str, size, format, (uintptr_t[]) {__NUMARGS_SPRINTF(__VA_ARGS__), ##__VA_ARGS__ })


static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_my_snprintf(void) {

    int bytes_written = 0;
    char buf[30];
    const char *expected_output = "Coucou 6-9";

    memset(buf, 0, sizeof(char) * 30);
    bytes_written = ubpf_sprintf(buf, 29, "Coucou %d-%d", 6, 9);

    CU_ASSERT_EQUAL(bytes_written, 10)
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 11)

}

static void test_my_snprintf_string(void) {

    int bytes_written = 0;
    const char *name = "Thomas";
    const char *expected_output = "Hello Thomas!";
    char buf[30];
    memset(buf, 0, sizeof(char) * 30);

    bytes_written = ubpf_sprintf(buf, 29, "Hello %s!", (uintptr_t) name);

    CU_ASSERT_EQUAL(bytes_written, 13);
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 14);

}

static void test_my_snprintf_mix(void) {

    int bytes_written = 0;
    int big_number = -65798;
    const char *name = "Thomas";
    const char *expected_output = "Hello Thomas! Big number is -65798";
    char buf[40];
    memset(buf, 0, sizeof(char) * 40);

    bytes_written = ubpf_sprintf(buf, 39, "Hello %s! Big number is %d", (uintptr_t) name, big_number);

    CU_ASSERT_EQUAL(bytes_written, 34);
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 35);

}

static void test_my_snprintf_overflow(void) {

    int bytes_written = 0;
    char buf[30];
    const char *expected_output = "Hello World! This is a long st";
    const char *string = "This is a long string";
    memset(buf, 0, sizeof(char) * 30);

    bytes_written = ubpf_sprintf(buf, 30, "Hello World! %s", (uintptr_t) string);

    CU_ASSERT_EQUAL(bytes_written, -1);
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 30);

}

static inline char *skip_trailing_zeroes(char *str) {

    while(*str == '0') str++;
    while(*str == 'x') str++;

    return str;
}

static void test_my_snprintf_ptr(void) {

    int bytes_written = 0;
    int expected_bytes_written = 0;
    char buf[30];
    char expected_buf[30];
    int test_ptr = 42;

    memset(buf, 0, sizeof(char) * 30);
    memset(expected_buf, 0, sizeof(char) * 30);

    expected_bytes_written = snprintf(expected_buf, 30, "%p", &test_ptr);
    bytes_written = ubpf_sprintf(buf, 30, "%p", (uintptr_t) &test_ptr);

    CU_ASSERT_NOT_EQUAL(bytes_written, 0);
    CU_ASSERT_NSTRING_EQUAL(skip_trailing_zeroes(buf), skip_trailing_zeroes(expected_buf), expected_bytes_written);

}


static char *get_dir_path(char *dir, size_t len) {
    char this_file_path[PATH_MAX];
    char real_path_this_file[PATH_MAX];
    strncpy(this_file_path, __FILE__, sizeof(this_file_path)-1);
    this_file_path[PATH_MAX-1] = 0;

    if (realpath(this_file_path, real_path_this_file) != real_path_this_file) {
        return NULL;
    };

    memset(dir, 0, len);

    strncpy(dir, dirname(real_path_this_file), len-1);
    dir[len-1] = 0;

    return dir;
}

static inline void id_file(char *buf, size_t len) {

    memset(buf, 0, len);

    char tmp_buf[PATH_MAX];
    char tmp_dir_buf[PATH_MAX];

    memset(tmp_buf, 0, sizeof(tmp_buf));

    get_dir_path(tmp_dir_buf, sizeof(tmp_dir_buf));

    if (snprintf(buf, len, "%s/id_test", tmp_dir_buf) >= (int) len) {
        fprintf(stderr, "Output is truncated! %s", __FUNCTION__ );
        return;
    }

    if (realpath(tmp_buf, buf)) {
        fprintf(stderr, "realpath failed\n");
    }
}

static void test_fetch_file_api_fun(void) {
    uint8_t one_byte = 1;
    int i, err;
    int fd_tmp, fd_urandom, fd_fetch;
    char name_tmp[] = "/tmp/test_ubpfXXXXXX";
    char template2[] = "/tmp/test_ubpfXXXXXX";
    char id_ssh_file[PATH_MAX];
    const char *urandom = "/dev/urandom";
    char *dest_buf, *fetch_buf;
    char *name_fetch;
    int length_file = 1048576; // (1MB)
    char url_rsync[PATH_MAX];

    // create temporary file
    fd_urandom = open(urandom, O_RDONLY);
    if (fd_urandom < 0) {
        perror("Unable to open /dev/urandom");
        CU_FAIL_FATAL("Unable to open /dev/urandom")
    }

    fd_tmp = mkstemp(name_tmp);
    if (fd_tmp < 0) {
        perror("mkstemp");
        CU_FAIL_FATAL("Unable to create tmpfile");
    }

    if ((fd_fetch = mkstemp(template2)) == -1) {
        perror("mkstemp");
        CU_FAIL_FATAL("Unable to create tmpfile");
    } else {
        name_fetch = template2;
    }

    // lseek to the end of the file
    if (lseek(fd_tmp, length_file - 1, SEEK_SET) == -1) {
        CU_FAIL_FATAL("Unable to fseek");
    }
    if (write(fd_tmp, &one_byte, sizeof(one_byte)) != sizeof(one_byte)) {
        CU_FAIL_FATAL("Unable to write");
    }
    // and lseek to the beginning
    if (lseek(fd_tmp, 0, SEEK_SET) == -1) {
        CU_FAIL_FATAL("Unable to fseek");
    }

    dest_buf = mmap(NULL, length_file, PROT_READ | PROT_WRITE, MAP_SHARED, fd_tmp, 0);
    if (dest_buf == MAP_FAILED) {
        perror("mmap");
        CU_FAIL_FATAL("Unable to mmap garbage file");
    }

    for (i = 0; i < length_file;) {
        err = read(fd_urandom, dest_buf + i, length_file - i);
        if (err == -1) {
            perror("read");
            CU_FAIL_FATAL("Unable to read from urandom");
        }
        i += err;
    }

    fsync(fd_tmp);
    close(fd_urandom);

    memset(url_rsync, 0, sizeof(url_rsync));
    snprintf(url_rsync, PATH_MAX, "rsync://localhost%s", name_tmp);

    id_file(id_ssh_file, sizeof(id_ssh_file));

    if (setenv("UBPF_IDENTITY_FILE", id_ssh_file, 1) != 0) {
        CU_FAIL_FATAL("Unable to change the environment variable");
    }

    if (fetch_file(NULL, url_rsync, name_fetch) == -1) {
        CU_FAIL_FATAL("Unable to fetch file")
    }

    // test if the two files are the same
    // fd_fetch = open(name_fetch, O_RDONLY);
    // if (fd_fetch < 0) {
    //     CU_FAIL_FATAL("Unable to open fetched file");
    // }

    // mmap because its simpler lol
    fetch_buf = mmap(NULL, length_file, PROT_READ, MAP_PRIVATE, fd_fetch, 0);

    if (fetch_buf == MAP_FAILED) {
        CU_FAIL_FATAL("Unable to fetch rsynced file")
    }

    unsetenv("UBPF_IDENTITY_FILE");

    CU_ASSERT_EQUAL(memcmp(dest_buf, fetch_buf, length_file), 0);

    // clean every structure that has been allocated
    munmap(dest_buf, length_file);
    munmap(fetch_buf, length_file);

    close(fd_tmp);
    close(fd_fetch);

    unlink(name_fetch);
    unlink(name_tmp);
}

static void test_dict(void) {
    char data1[] = "mydata";
    int forty_two = 42;
    int _val = 10;
    int *val = &_val;

    dict_t dict;
    dict_init(&dict);

    CU_ASSERT_PTR_NULL(dict);

    CU_ASSERT_PTR_NOT_NULL_FATAL(dict_add(&dict, data1, sizeof(data1) - 1, &forty_two, sizeof(forty_two)));
    CU_ASSERT_PTR_NOT_NULL_FATAL(dict_add(&dict, "data2", strlen("data2"), &val, sizeof(val)));

    _val = 56;
    forty_two = 43;

    int *ptr_42 = dict_get(&dict, "mydata");
    int *null_ptr = dict_get(&dict, "my_data");
    int **ptr_val = dict_get(&dict, "data2");

    CU_ASSERT_PTR_NOT_NULL_FATAL(ptr_42);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ptr_val);
    CU_ASSERT_PTR_NULL(null_ptr);

    CU_ASSERT_EQUAL(*ptr_42, 42);
    CU_ASSERT_EQUAL(**ptr_val, 56);

    dict_entry_del(&dict, "mydata");
    CU_ASSERT_PTR_NULL(dict_get(&dict, "mydata"));

    dict_del(&dict);
    CU_ASSERT_PTR_NULL(dict);
}

CU_ErrorCode internal_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("internal_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Custom snprintf", test_my_snprintf)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf overflow", test_my_snprintf_overflow)) ||
        (NULL == CU_add_test(pSuite, "Dict implem", test_dict)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf ptr", test_my_snprintf_ptr)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf mix", test_my_snprintf_mix)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf string", test_my_snprintf_string)) ||
        (NULL == CU_add_test(pSuite, "Fetch File API function", test_fetch_file_api_fun))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}