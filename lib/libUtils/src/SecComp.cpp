#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>

#include "glog/logging.h"

#include "SecComp.hpp"

int setup_seccomp() {
    struct sock_filter base_filter[] = {
        /* validate arch */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
        BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),

#ifdef SECCOMP_TRAP
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),

#else
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
#endif
        /* load syscall */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* Base allowed syscalls */
        Allow(exit_group),
        Allow(brk),
        Allow(mmap),
        Allow(munmap),
        Allow(write),
        Allow(fstat),
        Allow(gettimeofday),
        Allow(uname),

        // Required by our code:
        Allow(open),
        Allow(pread64),
        Allow(close),
        Allow(stat),
        Allow(read),
        Allow(lseek),
        Allow(openat),

        // For LOG(FATAL)
        Allow(rt_sigaction),
        Allow(rt_sigprocmask),
        Allow(getpid),
        Allow(gettid),
        Allow(tgkill),
        Allow(mremap),

#ifdef SECCOMP_TRAP
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),

#else
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
#endif
    };

    struct sock_fprog filterprog = {
        .len = sizeof(base_filter)/sizeof(base_filter[0]),
        .filter = base_filter
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        LOG(FATAL) << "Failed to setup restricted env";
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
        LOG(FATAL) << "Failed to install SECCOMP filter";
        return 1;
    }

    return 0;
}
