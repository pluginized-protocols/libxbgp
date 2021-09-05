CC=clang

XBGP_DEFS = /home/thomas/Documents/GitHub/xbgp_plugins

CFLAGS += -I../../ubpf_vm/vm
CFLAGS += -I../../ubpf_vm/vm/inc
CFLAGS += -I../..
CFLAGS += -I../../include
CFLAGS += -I$(XBGP_DEFS)

CFLAGS += -march=native -mtune=native
CFLAGS += -O2 -g
#CFLAGS += -O0 -g3
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

SRC = ebpf_insts_counter.c

OBJ = $(SRC:.c=.o)

LIBUBPF = ../../libubpf.a

LDLIBS += -ljson-c -pthread -lpthread -lrt -lffi
LDLIBS += -lncurses -ltinfo
LDLIBS += -lm

%.o: %.c
	@echo CC $@
	@$(CC) $(CFLAGS) -c -o $@ $<

ebpf_insts_counter: $(OBJ)
	@echo LD $@
	@$(CC) $(LDFLAGS) $(TARGET_ARCH) $^ $(LIBUBPF) $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: clean

clean: $(OBJ)
	rm $(OBJ)