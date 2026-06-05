SHELL := /bin/bash
.ONESHELL:

all: asm asm.tiny

asm: asm.s
	gcc -m32 -c -o $@.o $<
	ld -m elf_i386 --omagic --strip-all -o $@ $@.o

define make_tiny =
	@segment_offset="$(od -A n -j 56 -N 1 -t u1 asm | tr -d ' ')"
	@segment_size="$(od -A n -j 68 -N 1 -t u1 asm | tr -d ' ')"
	@total_bytes="$((${segment_offset} + ${segment_size}))"
	@echo Extracting "${total_bytes}" bytes from ELF file
	@dd bs=1 count=${total_bytes} if=asm of=asm.tiny 2>/dev/null
	@chmod +x asm.tiny
endef

asm.tiny: asm ; $(value make_tiny)

clean:
	rm -f asm.o asm asm.tiny
