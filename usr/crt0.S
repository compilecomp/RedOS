/* RedOS user-program entry stub (v0.8.0).
 *
 * The trampoline enters ring 3 with rsp = stack top (16-byte aligned) and
 * the capability slot in RDI. This stub aligns rsp for the SysV callee
 * convention (call pushes the return address, so cmain's entry sees
 * rsp ≡ 8 (mod 16)), forwards RDI, and never returns: programs exit via
 * SYS_EXIT, and reaching the loop below is a kernel-contract breach that
 * spins visibly (the scenario polls exit codes, so a stuck program is a
 * named timeout, not a silent pass).
 */
    .intel_syntax noprefix
    .text
    .globl _start
_start:
    and  rsp, -16
    call cmain
1:  jmp  1b
