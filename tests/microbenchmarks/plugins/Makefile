CC = clang
LLC = llc

CFLAGS += -I../../../xbgp_deps
CFLAGS += -I../../..
CFLAGS += -fno-stack-protector
CFLAGS += -Wall -Wextra
CFLAGS += -Wno-pedantic

CFLAGS += -DPLUGIN_MODE

OUTDIR=ebpf

SRC=$(shell find . -name '*.c')
OBJ=$(SRC:%.c=$(OUTDIR)/%.o)

all: outdir $(OBJ)

$(OBJ): $(OUTDIR)/%.o: %.c
	@echo CC_BPF $<
	@$(CC) $(CFLAGS) -O2 -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

outdir:
	@mkdir -p $(OUTDIR)

.PHONY: clean outdir

clean:
	rm -f $(OBJ)