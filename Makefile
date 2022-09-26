CC = clang

objects += src/loader.o
cmdobjects += src/fcmd.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o

LDFLAGS += -lconfig -lelf -lz

all: build_filter
build_filter: src/program.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/program.c -o src/program.bc
	llc -march=bpf -filetype=obj src/program.bc -o src/program.o

loader: libbpf $(objects)
	clang $(LDFLAGS) -o loader $(libbpf_static_objects) $(objects)

fcmd: libbpf $(cmdobjects)
	clang $(LDFLAGS) -o fcmd $(libbpf_static_objects) $(cmdobjects)

clean:
	rm -f src/*.o src/*.bc
	rm -f loader
	rm -f fcdmd

unload:
	sudo ip link set eno1 xdpgeneric off

load:
	sudo ip link set dev eno1 xdp obj src/program.o sec xdp_prog

.PHONY: libbpf all
.DEFAULT: all
