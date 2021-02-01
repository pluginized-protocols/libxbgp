CC = gcc
AR = ar
# CFLAGS += -march=native -mtune=native
# CFLAGS += -O2
CFLAGS += -O0 -g3
CFLAGS += -std=gnu11
CFLAGS += -Wall
CFLAGS += -Wshadow
CFLAGS += -Wextra
CFLAGS += -Wwrite-strings
CFLAGS += -Wcast-qual
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wmissing-declarations
CFLAGS += -Wpointer-arith
CFLAGS += -Wbad-function-cast

CFLAGS += -Iubpf_vm/vm/inc
CFLAGS += -Iinclude
CFLAGS += -I.
CFLAGS += -I/usr/local/include
CFLAGS += -I/usr/include/json-c

LDFLAGS += -L/usr/local/lib
LDFLAGS += -L.

LDLIBS += -Wl,-Bstatic -lcunit -lubpf -Wl,-Bdynamic
LDLIBS += -ljson-c -pthread -lpthread -lrt -lffi
LDLIBS += -lncurses -ltinfo
LDLIBS += -lm 

# ./dynamic_injection.c
# ./ebpf_injecter.c \
# ./main_ipfix_collector.c \
# ./main_ipfix_exporter.c \

SRC = ubpf_vm/vm/ubpf_jit_x86_64.c \
      ubpf_vm/vm/ubpf_loader.c \
      ubpf_vm/vm/ubpf_vm.c \
      ./bpf_plugin.c \
      ./insertion_point.c \
      ./list.c \
      ./map.c \
      ./log.c \
      ./plugin_extra_configuration.c \
      ./plugins_manager.c \
      ./queue.c \
      ./shared_memory.c \
      ./static_injection.c \
      ./tree.c \
      ./ubpf_api.c \
      ./ubpf_context.c \
      ./ubpf_manager.c \
      ./ubpf_memory_pool.c \
      ./ubpf_misc.c \
      ./url_parser.c


SRC_TESTS = $(shell find ./tests -name "*.c" -not -path "./tests/plugins/*")
HDR_TESTS = $(shell find ./tests -name "*.h")

HDR = ./bpf_plugin.h \
      ./dynamic_injection.h \
      ./insertion_point.h \
      ./list.h \
      ./monitoring_server.h \
      ./plugin_extra_configuration.h \
      ./plugins_manager.h \
      ./queue.h \
      ./shared_memory.h \
      ./static_injection.h \
      ./tree.h \
      ./ubpf_api.h \
      ./ubpf_context.h \
      ./ubpf_manager.h \
      ./ubpf_memory_pool.h \
      ./ubpf_misc.h \
      ./uthash.h \
      ./utlist.h \
      ./map.h \
      ./url_parser.h \
      ./log.h \
      include/bytecode_public.h \
      include/context_hdr.h \
      include/ebpf_mod_struct.h \
      include/global_info_str.h \
      include/monitoring_struct.h \
      include/plugin_arguments.h \
      include/tools_ubpf_api.h \
      include/ubpf_mempool_hdr.h \
      include/ubpf_prefix.h \
      include/ubpf_public.h


LIBUBPF_A = libubpf.a

OBJ = $(SRC:.c=.o)
OBJ_TESTS = $(SRC_TESTS:.c=.o)

all: libubpf.a

check: lib_tests

%.o: %.c %.h
	@echo CC $@
	@$(CC) $(CFLAGS) -c -o $@ $<

$(LIBUBPF_A): $(OBJ)
	@echo AR $@
	@$(AR) rcs $@ $^
	@ranlib $@

lib_tests: $(LIBUBPF_A) $(OBJ_TESTS)
	@echo ~~~ Compiling eBPF bytecode...
	@cd ./tests/plugins && $(MAKE)
	@echo ~~~ DONE !
	@echo LD $@
	@$(CC) $(LDFLAGS) $(TARGET_ARCH) $(OBJ_TESTS) $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: clean

clean:
	rm -f $(OBJ) $(OBJ_TESTS) $(LIBUBPF_A)
