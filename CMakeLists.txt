cmake_minimum_required(VERSION 3.15)
project(libxbgp_vm C)

set(CMAKE_C_STANDARD 11)
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(PLUGIN_TESTS_DIR "${TEST_DIR}/plugins")
set(MICHELFRALLOC_DIR "${CMAKE_SOURCE_DIR}/memalloc")
set(UBPF_VM_DIR "${CMAKE_SOURCE_DIR}/ubpf_vm/vm")

set(UBPF_VM_SOURCES
        ${UBPF_VM_DIR}/ubpf_jit_x86_64.c
        ${UBPF_VM_DIR}/ubpf_loader.c
        ${UBPF_VM_DIR}/ubpf_vm.c)

# Ugly hack since I don't want to have many includes for libxbgp...
# MICHELFRALLOC generates 2 static libs for 3 object files only...
add_custom_command(OUTPUT "${MICHELFRALLOC_DIR}/michelfralloc.o ${MICHELFRALLOC_DIR}/sbrk.o ${MICHELFRALLOC_DIR}/ptmalloc3/malloc.o"
        COMMAND make
        WORKING_DIRECTORY ${MICHELFRALLOC_DIR}
        )

set(MICHELFRA_OBJS
        "${MICHELFRALLOC_DIR}/michelfralloc.o"
        "${MICHELFRALLOC_DIR}/sbrk.o"
        "${MICHELFRALLOC_DIR}/ptmalloc3/malloc.o")

include_directories(.)
include_directories(include)
include_directories(ubpf_vm/vm)
include_directories(ubpf_vm/vm/inc)
include_directories(xbgp_deps)

set(CMAKE_C_FLAGS "-std=gnu11 -O2 -Wall -Wshadow
                   -Wextra -Wwrite-strings -Wcast-qual
                   -Wmissing-prototypes -Wmissing-declarations
                   -Wpointer-arith -Wbad-function-cast ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

add_library(xbgp
        ${UBPF_VM_SOURCES}
        ${MICHELFRA_OBJS}
        bpf_plugin.c bpf_plugin.h
        context_function.c context_function.h
        dict.c dict.h
        event.c event.h
        evt_plugins.c evt_plugins.h
        insertion_point.c insertion_point.h
        log.c log.h
        plugin_extra_configuration.c plugin_extra_configuration.h
        plugin_socket.c plugin_socket.h
        plugins_manager.c plugins_manager.h
        pluglet_validation.c pluglet_validation.h
        queue.c queue.h
        shared_memory.c shared_memory.h
        static_injection.c static_injection.h
        tree.c tree.h
        ubpf_api.c ubpf_api.h
        ubpf_context.c ubpf_context.h
        ubpf_manager.c ubpf_manager.h
        ubpf_memory_pool.c ubpf_memory_pool.h
        ubpf_misc.c ubpf_misc.h
        url_parser.c url_parser.h
        uthash.h utlist.h)

add_executable(libxbgp_tests ${TESTS_DIR}/main_tests.c
        ${TESTS_DIR}/extra_info_big.c ${TESTS_DIR}/extra_info_big.h
        ${TESTS_DIR}/extra_info_test.c ${TESTS_DIR}/extra_info_test.h
        ${TESTS_DIR}/ffi_closure_tests.c ${TESTS_DIR}/ffi_closure_tests.h
        ${TESTS_DIR}/internal_tests.c ${TESTS_DIR}/internal_tests.h
        ${TESTS_DIR}/job_plugins_tests.c ${TESTS_DIR}/job_plugins_tests.h
        ${TESTS_DIR}/mempool_tests.c ${TESTS_DIR}/mempool_tests.h
        ${TESTS_DIR}/monitoring_tests.c ${TESTS_DIR}/mempool_tests.h
        ${TESTS_DIR}/next_replace_tests.c ${TESTS_DIR}/next_replace_tests.h
        ${TESTS_DIR}/permissions_test.c ${TESTS_DIR}/permissions_test.h
        ${TESTS_DIR}/runtime_memcheck_test.c ${TESTS_DIR}/runtime_memcheck_test.h
        ${TESTS_DIR}/sockets_tests.c ${TESTS_DIR}/sockets_tests.h
        ${TESTS_DIR}/tree_test.c ${TESTS_DIR}/tree_test.h
        ${TESTS_DIR}/ubpf_manager_test.c ${TESTS_DIR}/ubpf_manager_test.h)

target_link_libraries(libxbgp_tests xbgp)

enable_testing()
add_test(Working_uBPF_VM libxbgp_tests -p ${PLUGIN_TESTS_DIR})