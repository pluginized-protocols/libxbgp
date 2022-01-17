CC = clang
LLC = llc

CFLAGS += -I../../xbgp_deps
CFLAGS += -I../..
CFLAGS += -fno-stack-protector
CFLAGS += -Wall -Wextra
CFLAGS += -Wno-pedantic

SRC=$(shell find . -name '*.c')
OBJ=$(SRC:.c=.o)

all: $(OBJ)

%.o: %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -O2 -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

.PHONY: clean

clean:
	rm -f $(OBJ)
