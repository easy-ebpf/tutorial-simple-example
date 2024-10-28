/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_open")
int handle_tp(void *ctx)
{

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);

    return 0;
}
