/* RedOS user-side syscall ABI (v0.8.0) — the mirror of kernel/syscall.rs.
 *
 * Register contract:
 *   rax = syscall number
 *   rdi, rsi, rdx, r8, r9 = payload registers (opaque to the kernel on
 *                           the IPC paths; the router moves, never reads)
 *   r10 = capability slot (authority handle, minted by the spawner into
 *         RDI at entry — the program passes it back on every IPC call)
 *   return: rax (0 = success on the IPC paths)
 *
 * Kernel-clobbered: rcx, r11 (hardware). No other register survives
 * undocumented state across a syscall — the kernel saves/restores all
 * sixteen GP registers it touches.
 */
#ifndef REDOS_SYS_H
#define REDOS_SYS_H

#define SYS_PING      0L
#define SYS_EXIT      1L
#define SYS_IPC_SEND  2L
#define SYS_IPC_RECV  3L

/* Full-ABI syscall: payload registers a1..a5, capability slot in r10. */
static inline long sys6(long n, long a1, long a2, long a3, long a4, long a5,
                        long cap) {
    register long r10_ __asm__("r10") = cap;
    register long r8_ __asm__("r8") = a4;
    register long r9_ __asm__("r9") = a5;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r8_), "r"(r9_),
                       "r"(r10_)
                     : "rcx", "r11", "memory");
    return ret;
}

/* RECV: the payload arrives in the payload registers themselves —
 * return all five plus rax. */
static inline long sys_recv(long cap, long out[5]) {
    register long r10_ __asm__("r10") = cap;
    register long r8_ __asm__("r8");
    register long r9_ __asm__("r9");
    long rax_, rdi_, rsi_, rdx_;
    __asm__ volatile("syscall"
                     : "=a"(rax_), "=D"(rdi_), "=S"(rsi_), "=d"(rdx_),
                       "=r"(r8_), "=r"(r9_)
                     : "a"(SYS_IPC_RECV), "r"(r10_)
                     : "rcx", "r11", "memory");
    out[0] = rdi_;
    out[1] = rsi_;
    out[2] = rdx_;
    out[3] = r8_;
    out[4] = r9_;
    return rax_;
}

/* Exit: never returns (the kernel kills the task inside the syscall). */
static inline void sys_exit(long code) {
    (void)sys6(SYS_EXIT, code, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

#endif /* REDOS_SYS_H */
