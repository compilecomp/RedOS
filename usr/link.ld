/* RedOS user-program link script (v0.8.0).
 *
 * USR_BASE is provided by --defsym (one 2 MiB slot per program inside
 * the kernel's user code window, PML4[252] — see kernel/mm/pagemap.rs).
 * Three PT_LOAD segments with explicit flags keep W^X true at the
 * segment level: text R+X, rodata R, data+bss R+W (never W+X).
 * Output sections start on fresh 4 KiB pages so the loader's
 * page-granular mapping never sees two segments claim one frame.
 */
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5); /* R + X */
    rodata PT_LOAD FLAGS(4); /* R     */
    data   PT_LOAD FLAGS(6); /* R + W */
}

SECTIONS
{
    . = USR_BASE;

    .text : ALIGN(4K) {
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(4K) {
        *(.data .data.* .got .got.*)
    } :data

    .bss : ALIGN(4K) {
        *(COMMON .bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
    }

    ASSERT(. <= USR_BASE + 2M, "user program exceeds its 2 MiB slot")
}
