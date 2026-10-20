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

CRYPTO_SRC   := crypto/src/aes.c crypto/src/gcm.c
CRYPTO_OBJ   := $(CRYPTO_SRC:crypto/src/%.c=build/%.o)
CRYPTO_LIB   := build/libredcrypto.a
KERNEL_ELF   := kernel/target/x86_64-unknown-none/release/redos-kernel

.PHONY: all crypto-test freestanding-check kernel bootloader image qemu \
        boot-test loc clean
all: crypto-test freestanding-check kernel bootloader

build/%.o: crypto/src/%.c crypto/include/red/crypto.h | build
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
	@und=$$($(NM) build/aes.free.o build/gcm.free.o | awk '$$1=="U"{print $$2}' | sort -u \
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
	cd kernel && cargo build --release
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
