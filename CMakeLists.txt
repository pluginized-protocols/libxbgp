cmake_minimum_required(VERSION 3.15)
project(libxbgp_vm C)

find_package(PkgConfig)
find_package(Threads)

set(CMAKE_C_STANDARD 11)
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(PLUGIN_TESTS_DIR "${TESTS_DIR}/plugins")
set(MICHELFRALLOC_DIR "${CMAKE_SOURCE_DIR}/memalloc")
set(UBPF_VM_DIR "${CMAKE_SOURCE_DIR}/ubpf_vm/vm")

set(UBPF_VM_SOURCES
        ${UBPF_VM_DIR}/ubpf_jit_x86_64.c
        ${UBPF_VM_DIR}/ubpf_loader.c
        ${UBPF_VM_DIR}/ubpf_vm.c)

# Ugly hack since I don't want to have many includes for libxbgp...
# MICHELFRALLOC generates 2 static libs for 3 object files only...
add_custom_command(OUTPUT ${MICHELFRALLOC_DIR}/michelfralloc.o
                          ${MICHELFRALLOC_DIR}/sbrk.o
                          ${MICHELFRALLOC_DIR}/ptmalloc3/malloc.o
                   COMMAND make clean && make
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

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE} -O2")

set(CMAKE_C_FLAGS_DEBUG  "-O0 -gdwarf -g3")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CC_WARNING_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-qual")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wbad-function-cast")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-prototypes")


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
        uthash.h utlist.h jhash.h)

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


pkg_check_modules(JSON-C REQUIRED json-c)
pkg_check_modules(FFI REQUIRED libffi)
pkg_check_modules(CUNIT REQUIRED cunit)

CHECK_LIBRARY_EXISTS(m sin "" HAVE_LIB_M)

if (HAVE_LIB_M)
    set(LIBM m)
endif (HAVE_LIB_M)

add_custom_target(gen_ebpf_test_obj COMMAND make
        WORKING_DIRECTORY ${PLUGIN_TESTS_DIR})

target_link_libraries(libxbgp_tests xbgp ${FFI_LIBRARIES}
        ${JSON-C_LIBRARIES} ${CUNIT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${LIBM})

add_dependencies(libxbgp_tests gen_ebpf_test_obj)


enable_testing()
add_test(Working_uBPF_VM libxbgp_tests -p ${PLUGIN_TESTS_DIR})