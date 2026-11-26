SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := guest
.DELETE_ON_ERROR:

export PROJECT_ROOT := $(CURDIR)
export PROJECT_BUILD := $(CURDIR)/build

target_dir := programs/$(PROGRAM)
guest_dir := build/guests/$(TARGET)
program := $(if $(wildcard $(target_dir)/main.c),$(guest_dir)/program)

.PHONY: guest
guest: $(guest_dir)/initramfs.cpio.gz

$(guest_dir)/initramfs.cpio.gz: targets/$(TARGET).conf initramfs/files initramfs/init $(target_dir)/init \
                             $(program) build/busybox/bin/busybox \
                             build/kernel/usr/gen_init_cpio scripts/guest.mk
	mkdir -p "$(@D)"
	{ cat initramfs/files; \
	  printf 'file /target %s 755 0 0\n' "$(CURDIR)/$(target_dir)/init"; \
	  if [[ -n "$(program)" ]]; then \
	      printf 'file /bin/program %s 755 0 0\n' "$(CURDIR)/$(program)"; \
	  fi; \
	} | build/kernel/usr/gen_init_cpio - | gzip -n > "$@.tmp"
	mv "$@.tmp" "$@"

$(guest_dir)/program: $(target_dir)/main.c targets/$(TARGET).conf scripts/guest.mk \
                      build/src/llvm/bin/clang build/src/llvm/bin/ld.lld
	mkdir -p "$(@D)"
	build/src/llvm/bin/clang --target=aarch64-linux-gnu -fuse-ld=lld \
	    -O2 -Wall -Wextra -ffreestanding -fno-stack-protector -fno-pie \
	    -nostdlib -static -Ibuild/kernel/usr/include \
	    -MMD -MP -MF "$@.d" -MT "$@" "$<" -o "$@"

-include $(guest_dir)/program.d
