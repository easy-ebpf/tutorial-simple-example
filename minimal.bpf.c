/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>

typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned long long dev;
unsigned long long ino;

SEC("tp/syscalls/sys_enter_open")
int handle_tp(void *ctx)
{

    struct bpf_pidns_info ns;

	bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));
    
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", ns.pid);

    return 0;
}
