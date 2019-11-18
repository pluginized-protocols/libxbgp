CC=clang
LLC=llc-7
CCT2=docker run -v$(shell pwd)/../..:/work  -w/work/ubpf_tools/plugins/ clangkittel clang-3.6
T2=docker run -v$(shell pwd)/../..:/work  -w/work/ubpf_tools/plugins/ clangkittel T2.exe

KITTEL=docker run -v$(shell pwd):/work  -w/work clangkittel llvm2kittel
KITTELFLAGS=--dump-ll --no-slicing --eager-inline --propagate-conditions

SRC=$(shell find . -name '*.c')
OBJ=$(SRC:.c=.o)
CFLAGS=-I../.. -I../../lib -Wall -Wextra

LLOBJ=$(SRC:.c=.ll)
BCOBJ=$(SRC:.c=.bc)
T2OBJ=$(BCOBJ:.bc=.t2)

LOGPROOF=$(T2OBJ:.t2=.log_proof)

FRRCONFIG_DIR=/home/thomas/frrbuild/etc/frr

all: $(SRC) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -fno-stack-protector -O2 -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

%.bc: %.c
	$(CCT2) $(CFLAGS) -O0 -emit-llvm -c $< -o $@

%.t2: %.bc
	$(KITTEL) $(KITTELFLAGS) --t2 $< > $@

%.log_proof: %.t2
	$(T2) -input_t2 $< -termination &> $@

proof: $(SRC) $(BCOBJ) $(T2OBJ) $(LOGPROOF)

copy: $(OBJ)
	cp ./list_plugins.json $(FRRCONFIG_DIR)/list_plugins.json
	chmod 640 $(FRRCONFIG_DIR)/list_plugins.json
	chown frr:frr $(FRRCONFIG_DIR)/list_plugins.json
	cp $(OBJ) $(FRRCONFIG_DIR)/plugins
	chmod 440 $(FRRCONFIG_DIR)/plugins/*.o
    chown frr:frr $(FRRCONFIG_DIR)/plugins/*.o

clean:
	rm -f $(OBJ) $(BCOBJ) $(T2OBJ) $(LLOBJ) *.ll *.t2 *.bc

.PHONY: all proof copy clean 
