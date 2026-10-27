/* RedOS fault-containment demo (v0.8.0 user program).
 *
 * Dereferences an unmapped address in ring 3. The kernel's containment
 * path kills THIS task (named forensic line, exit marker recorded) and
 * the rest of the system continues — the sandbox story in ten lines.
 * The exit call below is unreachable by design: the #PF fires first.
 */
#include "sys.h"

long cmain(long cap)
{
    (void)cap;
    /* The dereference must be invisible to the optimizer (it WOULD be UB
     * at compile time and gcc -Werror refuses the direct form) — the load
     * is emitted as an opaque instruction instead: same fault, zero
     * compile-time undefined behavior. */
    long v;
    __asm__ volatile("movq 8, %0" : "=r"(v) :: "memory");
    sys_exit(v & 0xFFL);
    return 0;
}
