#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/*
 * Layers 4 & 5: Linux Kernel Hardening (SELinux / AppArmor Mandatory Access Control)
 * and eBPF LSM (Linux Security Module) Telemetry & Escape Blocker in Pure ANSI C11.
 */

typedef enum {
    LSM_ALLOW_EXECUTION = 0,
    LSM_DENY_EBPF_CAP_ESCAPE = 1,
    LSM_DENY_SELINUX_TYPE_ENFORCEMENT = 2,
    LSM_DENY_UNAUTHORIZED_KERNEL_MODULE = 3
} LsmSecurityDecision;

typedef struct {
    uint32_t pid;
    uint32_t uid;
    char selinux_context[64];
    char apparmor_profile[64];
    char syscall_name[32];
    char target_device_path[64];
    bool in_unprivileged_container;
} EbpfSyscallEvent;

LsmSecurityDecision evaluate_ebpf_selinux_hook(const EbpfSyscallEvent *ev) {
    /* 1. Block unsigned kernel module loading or kexec reboot on GPU cluster nodes */
    if (strcmp(ev->syscall_name, "init_module") == 0 ||
        strcmp(ev->syscall_name, "finit_module") == 0 ||
        strcmp(ev->syscall_name, "kexec_load") == 0) {
        return LSM_DENY_UNAUTHORIZED_KERNEL_MODULE;
    }

    /* 2. Block container escape attempts via ptrace or host namespace manipulation */
    if (ev->in_unprivileged_container &&
        (strcmp(ev->syscall_name, "ptrace") == 0 || strcmp(ev->syscall_name, "setns") == 0)) {
        return LSM_DENY_EBPF_CAP_ESCAPE;
    }

    /* 3. Enforce SELinux Type Enforcement for direct /dev/nvidia* device access */
    if (strncmp(ev->target_device_path, "/dev/nvidia", 11) == 0) {
        if (strstr(ev->selinux_context, "nvidia_hpc_job_t") == NULL &&
            strstr(ev->selinux_context, "slurm_ daemon_t") == NULL) {
            return LSM_DENY_SELINUX_TYPE_ENFORCEMENT;
        }
    }

    return LSM_ALLOW_EXECUTION;
}

int main(void) {
    EbpfSyscallEvent legitimate_job = {
        .pid = 48120,
        .uid = 10042,
        .selinux_context = "system_u:system_r:nvidia_hpc_job_t:s0:c10,c20",
        .apparmor_profile = "enroot-gpu-restricted (enforce)",
        .syscall_name = "ioctl",
        .target_device_path = "/dev/nvidiactl",
        .in_unprivileged_container = true
    };
    assert(evaluate_ebpf_selinux_hook(&legitimate_job) == LSM_ALLOW_EXECUTION);

    EbpfSyscallEvent rogue_escape = {
        .pid = 99102,
        .uid = 10099,
        .selinux_context = "unconfined_u:unconfined_r:container_t:s0",
        .apparmor_profile = "docker-default (enforce)",
        .syscall_name = "ioctl",
        .target_device_path = "/dev/nvidia0",
        .in_unprivileged_container = true
    };
    assert(evaluate_ebpf_selinux_hook(&rogue_escape) == LSM_DENY_SELINUX_TYPE_ENFORCEMENT);

    EbpfSyscallEvent rootkit_insmod = {
        .pid = 6660,
        .uid = 0,
        .selinux_context = "system_u:system_r:unconfined_t:s0",
        .apparmor_profile = "unconfined",
        .syscall_name = "finit_module",
        .target_device_path = "/lib/modules/rogue.ko",
        .in_unprivileged_container = false
    };
    assert(evaluate_ebpf_selinux_hook(&rootkit_insmod) == LSM_DENY_UNAUTHORIZED_KERNEL_MODULE);

    printf("[LAYERS 4-5 C11 eBPF & SELINUX/APPARMOR LSM] Kernel Hardening & Syscall Hooks Verified!\n");
    return 0;
}
