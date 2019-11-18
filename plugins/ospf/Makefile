SRC=$(wildcard *.c) # list of all .c files
OBJ=$(SRC:.c=.o) # for each .c file get a .o file
CFLAGS= -I/home/router/lib -I../.. -I/usr/include/frr -I/root/frr
LDFLAGS= #-L@top_srcdir@/lib -L@top_srcdir@/ospfd -L@top_srcdir@/ubpf/vm -L@top_srcdir@/pimd -lpim -lubpf -lfrrospf -lfrr

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c # .o constructed for dependance .c
	clang-6.0 $(CFLAGS) $(LDFLAGS) -fno-stack-protector -O2 -emit-llvm -c $< -o - | /usr/lib/llvm-6.0/bin/llc -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o # dependances systematically reconstructed
