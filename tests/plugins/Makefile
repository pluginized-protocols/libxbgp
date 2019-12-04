CC = clang
LLC = llc

CFLAGS += -I../../include
CFLAGS += -I../..

SRC=$(shell find . -name '*.c')
OBJ=$(SRC:.c=.o)

all: $(OBJ)

%.o: %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -Weverything -O2 -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

.PHONY: clean

clean:
	rm -f $(OBJ)