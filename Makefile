CC = gcc
AR = ar
CFLAGS += -O2
CFLAGS += -std=c99
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
LDFLAGS += -lm

SRC = $(shell find . -name '*.c' -not -path "./plugins/*" -not -path "./misc/*")
OBJ = $(SRC:.c=.o)

%.o: %.c
	@$(CC) $(CFLAGS) -o $@ $<
	@echo CC $@

libubpf.a: $(OBJ)
	$(ar) rcs $@ $^
