/* RedOS fast-path client (v0.8.0 user program).
 *
 * Protocol: PING round trip, then one register-path SEND of the protocol
 * constants to the endpoint named by our spawner-minted capability. The
 * server verifies them — the kernel moved the registers blind. Exit code
 * bits:
 *   bit0 = PING mismatch
 *   bit1 = send refused (capability/rights/second-sender)
 */
#include "sys.h"

#define PING_MAGIC   0x123456789ABCDEFL
#define PING_XOR     0x5A5A5A5A5A5A5A5AL

/* Must match srv.c — the programs' shared protocol, unknown to the
 * kernel's routing logic (fastpath.rs moves [u64;5] opaquely). */
static const long PAYLOAD[5] = { 0xA11CEL, 0x0B0BL, 0x0C0DEL, 0x0D00DL, 0x0E11L };

long cmain(long cap)
{
    long r = sys6(SYS_PING, PING_MAGIC, 0, 0, 0, 0, 0);
    int ping_ok = (r == (PING_MAGIC ^ PING_XOR));

    long rc = sys6(SYS_IPC_SEND, PAYLOAD[0], PAYLOAD[1], PAYLOAD[2],
                   PAYLOAD[3], PAYLOAD[4], (long)cap);

    sys_exit((ping_ok ? 0L : 1L) | (rc == 0 ? 0L : 2L));
    return 0;
}
