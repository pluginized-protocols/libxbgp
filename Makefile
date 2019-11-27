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
CFLAGS += -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
CFLAGS += -I/usr/include/libmongoc-1.0 -I/usr/include/libbson-1.0

LDFLAGS += -lm

SRC = queue.c ubpf_manager.c ebpf_injecter.c map.c ubpf_context.c plugins_manager.c \
      ubpf_vm/vm/ubpf_jit_x86_64.c ubpf_vm/vm/ubpf_loader.c ubpf_vm/vm/ubpf_vm.c bpf_plugin.c \
      list.c ubpf_api.c shared_memory.c monitoring_server.c hashmap.c


HDR = vm_macros.h include/ebpf_mod_struct.h include/plugin_arguments.h include/public.h include/monitoring_struct.h \
      include/public_bpf.h include/decision_process_manager.h include/tools_ubpf_api.h include/plugins_id.h \
      ubpf_api.h shared_memory.h hashmap.h monitoring_server.h ipfix_collector.h monitor_manager.h list.h \
      ubpf_context.h bgp_ipfix.h csnt_monitor.h bgp_ipfix_templates.h ubpf_vm/vm/ebpf.h ubpf_vm/vm/inc/ubpf.h \
      ubpf_vm/vm/ubpf_jit_x86_64.h ubpf_vm/vm/ubpf_int.h ubpf_prereq.h bpf_plugin.h plugins_manager.h \
      plugins/ospf/plugins.h queue.h map.h memory_manager.h ubpf_manager.h

OBJ = $(SRC:.c=.o)

all: libubpf.a

%.o: %.c %.h
	@echo CC $@
	@$(CC) $(CFLAGS) -c $< -o $@

libubpf.a: $(OBJ)
	@echo AR $@
	@$(AR) rcs $@ $^

.PHONY: clean

clean:
	rm -f $(OBJ)
