/* RedOS fast-path server (v0.8.0 user program).
 *
 * Protocol: PING round trip first (proves the syscall/sysret path under
 * load), then park in a register-path RECV. When the client's send
 * delivers, verify the payload against the constants BELOW — the
 * verification lives HERE, in user code: the kernel moved five words it
 * never looked at. Exit code bits (the kernel's scenario layer reads
 * them via SYS_EXIT):
 *   bit0 = PING mismatch
 *   bit2 = payload mismatch / recv error
 */
#include "sys.h"

#define PING_MAGIC   0x123456789ABCDEFL
#define PING_XOR     0x5A5A5A5A5A5A5A5AL

/* The rendezvous protocol constants — THIS program's private data. */
static const long PAYLOAD[5] = { 0xA11CEL, 0x0B0BL, 0x0C0DEL, 0x0D00DL, 0x0E11L };

long cmain(long cap)
{
    long expect = PING_MAGIC ^ PING_XOR;
    long r = sys6(SYS_PING, PING_MAGIC, 0, 0, 0, 0, 0);
    int ping_ok = (r == expect);

    long out[5];
    long rc = sys_recv((long)cap, out);
    int recv_ok = (rc == 0);
    for (int i = 0; i < 5; i++) {
        if (out[i] != PAYLOAD[i]) {
            recv_ok = 0;
        }
    }

    sys_exit((ping_ok ? 0L : 1L) | (recv_ok ? 0L : 4L));
    return 0;
}
