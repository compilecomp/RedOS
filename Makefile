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
	        -Icrypto/include

# Kernel-grade freestanding flags. The -mno-* set is x86_64-specific
# (CEP&CC Law 7: target-dependent flags live in exactly one place).
FREE_CFLAGS  := -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
	        -ffreestanding -fno-builtin -fno-stack-protector \
	        -Icrypto/include
ifeq ($(UNAME_M),x86_64)
FREE_CFLAGS += -mno-red-zone -mno-mmx -mno-sse -mno-sse2
endif

CRYPTO_SRC   := crypto/src/aes.c crypto/src/gcm.c crypto/src/blake2b.c \
	        crypto/src/argon2.c crypto/src/xts.c
CRYPTO_OBJ   := $(CRYPTO_SRC:crypto/src/%.c=build/%.o)
CRYPTO_LIB   := build/libredcrypto.a
KERNEL_ELF   := kernel/target/x86_64-unknown-none/release/redos-kernel

.PHONY: all crypto-test freestanding-check kernel bootloader image qemu \
	boot-test secret-audit loc clean
all: crypto-test freestanding-check kernel bootloader

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
kernel: | build
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
