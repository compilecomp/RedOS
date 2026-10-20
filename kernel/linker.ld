/* RedOS kernel linker script.
 *
 * The Zig bootloader loads PT_LOAD segments at their p_paddr (identity map),
 * so virtual == physical here. KERNEL_BASE = 0x200000 must match
 * bootloader/src/main.zig and kernel/.cargo/config.toml assumptions.
 *
 * CEP&CC Law 7: every kernel address assumption is stated here and asserted
 * by the bootloader's ELF range check at load time.
 */
ENTRY(_start)

KERNEL_BASE = 0x200000;

SECTIONS
{
    . = KERNEL_BASE;

    .text : ALIGN(4K)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata : ALIGN(4K)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.eh_frame .eh_frame.*)   /* LLVM exception-frame tables: read-only */
        __rodata_end = .;
    }

    .data : ALIGN(4K)
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
        __data_end = .;
    }

    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(COMMON .bss .bss.*)
        __bss_end = .;
    }

    __kernel_end = .;

    /* Fail the link if the kernel grows past the bootloader's checked
     * load window (bootloader allows up to 4 MiB from KERNEL_BASE). */
    ASSERT(__kernel_end <= 0x600000, "kernel exceeds 4 MiB load window")
}
