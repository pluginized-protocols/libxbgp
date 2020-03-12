CC = gcc
AR = ar
CFLAGS += -O2
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
LDLIBS += -ljson-c -pthread -lpthread -lrt
LDLIBS += -lncurses -ltinfo
LDLIBS += -lm 

SRC = queue.c ubpf_manager.c map.c ubpf_context.c plugins_manager.c \
      ubpf_vm/vm/ubpf_jit_x86_64.c ubpf_vm/vm/ubpf_loader.c ubpf_vm/vm/ubpf_vm.c bpf_plugin.c \
      list.c ubpf_api.c shared_memory.c monitoring_server.c hashmap.c tree.c ubpf_misc.c \
      ubpf_memory_pool.c

SRC_TESTS = $(shell find ./tests -name "*.c" -not -path "./tests/plugins/*")
HDR_TESTS = $(shell find ./tests -name "*.h")

HDR = vm_macros.h include/ebpf_mod_struct.h include/plugin_arguments.h include/public.h include/monitoring_struct.h \
      include/public_bpf.h include/tools_ubpf_api.h include/plugins_id.h \
      ubpf_api.h shared_memory.h hashmap.h monitoring_server.h monitor_manager.h list.h \
      ubpf_context.h ubpf_vm/vm/ebpf.h ubpf_vm/vm/inc/ubpf.h \
      ubpf_vm/vm/ubpf_jit_x86_64.h ubpf_vm/vm/ubpf_int.h ubpf_misc.h bpf_plugin.h plugins_manager.h \
      queue.h map.h memory_manager.h ubpf_manager.h tree.h ubpf_misc.h ubpf_memory_pool.h

LIBUBPF_A = libubpf.a

OBJ = $(SRC:.c=.o)
OBJ_TESTS = $(SRC_TESTS:.c=.o)

all: libubpf.a

check: lib_tests

%.o: %.c %.h
	@echo CC $@
	@$(CC) -g $(CFLAGS) -c -o $@ $<

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
