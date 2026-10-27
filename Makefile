# RedOS top-level build orchestration.
#
# CEP&CC note: this Makefile is CEP-2 tooling. All recipe failures are
# explicit (make -e semantics; each recipe must propagate errors).

CC      ?= cc
AR      ?= ar
NM      ?= nm
QEMU    ?= qemu-system-x86_64
OVMF_DIR ?= /usr/share/OVMF

UNAME_M := $(shell uname -m)

# Host build flags (CEP&CC 6.3: warnings are errors)
HOST_CFLAGS  := -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
                -fcf-protection=none \
	        -Icrypto/include

# Kernel-grade freestanding flags. The -mno-* set is x86_64-specific
# (CEP&CC Law 7: target-dependent flags live in exactly one place).
FREE_CFLAGS  := -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
	        -ffreestanding -fno-builtin -fno-stack-protector \
		-fcf-protection=none \
	        -Icrypto/include
ifeq ($(UNAME_M),x86_64)
FREE_CFLAGS += -mno-red-zone -mno-mmx -mno-sse -mno-sse2
endif

CRYPTO_SRC   := crypto/src/aes.c crypto/src/gcm.c crypto/src/blake2b.c \
	        crypto/src/argon2.c crypto/src/xts.c
CRYPTO_OBJ   := $(CRYPTO_SRC:crypto/src/%.c=build/%.o)
CRYPTO_LIB   := build/libredcrypto.a
KERNEL_ELF   := kernel/target/x86_64-unknown-none/release/redos-kernel

# User program bases: one 2 MiB slot per program inside the user code
# window (PML4[252] = 0x7800_0000_0000) - MUST match
# kernel/src/identity.rs (SRV_BASE/CLI_BASE/FAULTY_BASE).
USR_CODE_BASE := 0x780000000000
SRV_BASE      := 0x780000200000
CLI_BASE      := 0x780000400000
FAULTY_BASE   := 0x780000600000
# Freestanding static user images: large code model (VAs far above 2
# GiB), no PIE, W^X enforced by the linker script's PHDRS flags.
USR_CFLAGS := -nostdlib -static -ffreestanding -fno-pic -fno-pie -mcmodel=large \
              -fno-stack-protector -fcf-protection=none -O2 -Wall -Wextra \
              -Werror -Iusr

.PHONY: all crypto-test freestanding-check usr-programs kernel bootloader image qemu \
	boot-test secret-audit fastpath-audit loc clean
all: crypto-test freestanding-check kernel bootloader

build/usr/srv.elf: usr/srv.c usr/sys.h usr/crt0.S usr/link.ld | build/usr
	$(CC) $(USR_CFLAGS) -T usr/link.ld -Wl,--defsym=USR_BASE=$(SRV_BASE) \
		-o $@ usr/crt0.S usr/srv.c

build/usr/cli.elf: usr/cli.c usr/sys.h usr/crt0.S usr/link.ld | build/usr
	$(CC) $(USR_CFLAGS) -T usr/link.ld -Wl,--defsym=USR_BASE=$(CLI_BASE) \
		-o $@ usr/crt0.S usr/cli.c

build/usr/faulty.elf: usr/faulty.c usr/sys.h usr/crt0.S usr/link.ld | build/usr
	$(CC) $(USR_CFLAGS) -T usr/link.ld -Wl,--defsym=USR_BASE=$(FAULTY_BASE) \
		-o $@ usr/crt0.S usr/faulty.c

usr-programs: build/usr/srv.elf build/usr/cli.elf build/usr/faulty.elf
	@echo "USR-PROGRAMS OK (srv cli faulty: static ELF64, W^X segments)"

build/usr:
	mkdir -p build/usr

build/%.o: crypto/src/%.c crypto/include/red/crypto.h \
	   crypto/include/red/blake2b.h crypto/include/red/argon2.h \
	   crypto/include/red/xts.h | build
	$(CC) $(HOST_CFLAGS) -c $< -o $@

build:
	mkdir -p build

$(CRYPTO_LIB): $(CRYPTO_OBJ)
	$(AR) rcs $@ $^

build/test_vectors: tests/crypto/test_vectors.c $(CRYPTO_LIB)
	$(CC) $(HOST_CFLAGS) $< $(CRYPTO_LIB) -o $@

# Host test: FIPS-197 ECB KAT, NIST GCM TC13-16, tamper, aliasing, contracts
crypto-test: build/test_vectors
	./build/test_vectors

# Prove the C core is genuinely freestanding:
#  (a) compiles with kernel-grade flags, no libc headers beyond stdint/stddef
#  (b) object files have NO undefined symbols beyond the red_* project API
#      (link-level enforcement of the "no hidden libc calls" claim, Law 1)
freestanding-check: | build
	$(CC) $(FREE_CFLAGS) -c crypto/src/aes.c -o build/aes.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/gcm.c -o build/gcm.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/blake2b.c -o build/blake2b.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/argon2.c -o build/argon2.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/xts.c -o build/xts.free.o
	@und=$$($(NM) build/aes.free.o build/gcm.free.o build/blake2b.free.o build/argon2.free.o build/xts.free.o | awk '$$1=="U"{print $$2}' | sort -u \
	   | grep -v '^red_'); \
	 if [ -n "$$und" ]; then \
	   echo "FREESTANDING-CHECK FAILED: non-project undefined symbols:"; echo "$$und"; exit 1; \
	 fi
	@echo "FREESTANDING-CHECK OK (no undefined symbols beyond red_* API)"

# --- Phase 1 boot pipeline -------------------------------------------------

# Rust no_std microkernel (zero third-party deps in Phase 1)
# NOTE: build from kernel/ so cargo picks up kernel/.cargo/config.toml
# (target pin, linker script). --manifest-path from the root would skip it.
# The user ELFs are embedded (include_bytes!) - build them FIRST.
kernel: usr-programs | build
	$(CC) $(FREE_CFLAGS) -c crypto/src/aes.c -o build/aes.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/gcm.c -o build/gcm.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/blake2b.c -o build/blake2b.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/argon2.c -o build/argon2.free.o
	$(CC) $(FREE_CFLAGS) -c crypto/src/xts.c -o build/xts.free.o
	$(AR) rcs build/libredcrypto.free.a build/aes.free.o build/gcm.free.o build/blake2b.free.o build/argon2.free.o build/xts.free.o
	cd kernel && cargo rustc --release -- -C link-arg=-L../build -C link-arg=-lredcrypto.free
	cp kernel/target/x86_64-unknown-none/release/redos-kernel build/redos.bin

# Zig UEFI stage-0 bootloader (must match kernel/linker.ld KERNEL_BASE)
bootloader: | build
	zig build-exe bootloader/src/main.zig -target x86_64-uefi \
	    -O ReleaseSafe -femit-bin=build/BOOTX64.EFI

# FAT ESP image: BOOTX64.EFI + kernel ELF at \redos.bin
image: bootloader kernel | build
	truncate -s 16M build/esp.img
	mformat -i build/esp.img -C -h 32 -t 32 -s 32 ::
	mmd -i build/esp.img ::/EFI ::/EFI/BOOT
	mcopy -i build/esp.img build/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i build/esp.img build/redos.bin ::/redos.bin
	@echo "ESP image ready: build/esp.img"

# Interactive boot (serial console on stdout; Ctrl-C to quit)
qemu: image
	cp $(OVMF_DIR)/OVMF_VARS_4M.fd build/OVMF_VARS.fd
	$(QEMU) -machine q35 -m 512M -display none -no-reboot -serial stdio \
	    -L $${QEMU_DATA_DIR:-/usr/share/qemu} \
	    -drive if=pflash,format=raw,readonly=on,file=$(OVMF_DIR)/OVMF_CODE_4M.fd \
	    -drive if=pflash,format=raw,file=build/OVMF_VARS.fd \
	    -drive format=raw,file=build/esp.img

# Headless boot test: asserts bootloader + kernel serial banner (CI target)
boot-test: image
	OVMF_DIR=$(OVMF_DIR) scripts/boot_test.sh

# Secret audit (v0.7.0): the kernel binary must carry NO operator PIN.
# The vault PIN arrives through the input service at boot (operator on
# hardware; the CI feeder types the documented test PIN). The wrong-PIN
# vector inside the kernel is a public counter-probe input, not a secret.
# The CI feeder's PIN lives in scripts/boot_test.sh — test-harness data.
# Fast-path instruction-budget audit (v0.8.0): the 100-cycle-per-hop
# budget's hard evidence. TCG cannot certify hardware cycles, but the
# PATH LENGTH is a build artifact: count the instructions between the
# syscall entry stub, the dispatch, and the fast-path send handler in
# the LINKED kernel (objdump). A regressed (bloated) fast path fails
# this target, not a reviewer's patience. Budget: 200 per hop (entry +
# dispatch + exit ~ 100 at >=1 IPC/cycle; the send handler adds the cap
# check + delivery; the ceiling is documented in docs/ARCHITECTURE.md).
fastpath-audit: kernel
	@if [ ! -f "$(KERNEL_ELF)" ]; then echo "FASTPATH-AUDIT FAILED: kernel ELF missing"; exit 1; fi; \
	 nm $$(pwd)/$(KERNEL_ELF) | awk '{print $$1, $$3}' | sort > build/fastpath.syms; \
	 addr_of() { grep " $$1$$" build/fastpath.syms | awk '{print $$1}'; }; \
	 count_range() { objdump -d --start-address=0x$$1 --stop-address=0x$$2 $(KERNEL_ELF) 2>/dev/null | grep -cE '^[[:space:]]*[0-9a-f]+:'; }; \
	 count_fn() { zhex=$$(nm -S --defined-only $$(pwd)/$(KERNEL_ELF) | grep " $$1$$" | awk '{print $$2}'); \
	   if [ -z "$$zhex" ]; then echo "FASTPATH-AUDIT FAILED: $$1 has no ELF size"; exit 1; fi; \
	   z=$$((0x$$zhex)); a=$$(addr_of $$1); \
	   objdump -d --start-address=0x$$a --stop-address=$$((0x$$a + $$z)) $(KERNEL_ELF) 2>/dev/null | grep -cE '^[[:space:]]*[0-9a-f]+:'; }; \
	 E=$$(count_range $$(addr_of redos_syscall_entry) $$(addr_of redos_syscall_end)); \
	 W=$$(count_range $$(addr_of switch_to) $$(addr_of redos_switch_to_end)); \
	 D=$$(count_fn redos_syscall_dispatch); \
	 S=$$(count_fn redos_fp_sys_send); \
	 R=$$(count_fn redos_fp_sys_recv); \
	 TOTAL=$$((E + D + S + R + W)); \
	 echo "FASTPATH-AUDIT: entry-stub=$$E, dispatch=$$D, sys_send=$$S, sys_recv=$$R, switch_to=$$W"; \
	 echo "FASTPATH-AUDIT: conservative whole-rendezvous total = $$TOTAL instructions (budget 300)"; \
	 if [ $$TOTAL -gt 300 ]; then echo "FASTPATH-AUDIT FAILED: fast path exceeds the 300-instruction ceiling"; exit 1; fi

secret-audit: kernel
	@if grep -aq "sovereign-pin" build/redos.bin; then echo "SECRET-AUDIT FAILED: operator PIN string found in kernel binary"; exit 1; fi; echo "SECRET-AUDIT OK (no operator PIN in kernel binary; wrong-pin vector is public by design)"

# LOC ledger per component (raw line counts; see docs/ROADMAP.md targets)
loc:
	@printf "%-14s %8s\n" COMPONENT LOC
	@printf "%-14s %8s\n" ---------- --------
	@for d in bootloader kernel crypto proof tests; do \
	   if [ -d "$$d" ]; then \
	     n=$$(find $$d -type f \( -name '*.c' -o -name '*.h' -o -name '*.rs' \
	        -o -name '*.zig' -o -name '*.thy' \) -exec cat {} + 2>/dev/null | wc -l); \
	     printf "%-14s %8s\n" $$d $$n; \
	   fi; \
	 done

clean:
	rm -rf build
