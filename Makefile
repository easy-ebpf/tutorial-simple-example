run:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -O2 -g -target bpf -c minimal.bpf.c -o minimal.bpf.o
	bpftool gen skeleton minimal.bpf.o > minimal.skel.h
	clang -Wall -O2 minimal.c -o minimal -lbpf -lelf -lz
	./minimal

trace:
	bpftool prog trace log

clean:
	rm -rf *.o
	rm -rf minimal.skel.h
	rm -rf vmlinux.h
