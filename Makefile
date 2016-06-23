#
# Reverse engineer the thinkpad dosflash utility
#
# Copyright (C) 2016 Hamish Coleman
#
CFLAGS:=-Wall

all: kvm_flat
	$(info See README file for additional details)

.PHONY: all

#
# Radare didnt seem to let me specify the directory to store the project file,
# so this target hacks around that
#
install.radare.projects:
	mkdir -p ~/.config/radare2/projects/g2uj23us.dosflash.exe.d
	cp -fs $(PWD)/radare/g2uj23us.dosflash.exe ~/.config/radare2/projects
	mkdir -p ~/.config/radare2/projects/g2uj23us.dosflash.flat.d
	cp -fs $(PWD)/radare/g2uj23us.dosflash.flat ~/.config/radare2/projects

# Download any ISO image that we have a checksum for
# NOTE: makes an assumption about the Lenovo URL not changing
%.iso.orig:  %.iso.orig.sha1
	wget -O $@ https://download.lenovo.com/pccbbs/mobiles/$(basename $@)
	sha1sum -c $<
	touch $@

# All the bios update iso images I have checked have had a fat16 filesystem
# embedded in a dos mbr image as the el-torito ISO payload.  They also all
# had the same offset to this fat filesystem, so hardcode that offset here.
FAT_OFFSET := 71680

%.dosflash.exe.orig: %.iso.orig
	MTOOLS_SKIP_CHECK=1 mcopy -i $^@@$(FAT_OFFSET) ::FLASH/DOSFLASH.EXE $@

%.dosflash.coff.orig: %.dosflash.exe.orig
	./dump_exe.pl $< output_extra >$@

%.dosflash.flat.orig: %.dosflash.coff.orig
	./dump_coff.pl $< write_flat $@

# TODO - could parse dosflash.config to extract deps

%.dosflash.flat.test: %.dosflash.flat.orig kvm_flat dosflash.config bios.img
	./kvm_flat $< dosflash.config

# A copy of some low memory, including all the bios ROMS
bios.img:
	sudo dd if=/dev/mem of=bios.img bs=65536 skip=12 count=4

MEMMAP_ACPI = $(dir $(shell egrep -l "ACPI Tables" /sys/firmware/memmap/*/type))
MEMMAP_ACPINV = $(dir $(shell egrep -l "ACPI Non-volatile Storage" /sys/firmware/memmap/*/type))

ACPI_START = $(shell cat $(MEMMAP_ACPI)/start)
ACPI_END = $(shell cat $(MEMMAP_ACPI)/end)
ACPI_LEN = $(ACPI_END) - $(ACPI_START) +1

ACPINV_START = $(shell cat $(MEMMAP_ACPINV)/start)
ACPINV_END = $(shell cat $(MEMMAP_ACPINV)/end)
ACPINV_LEN = $(ACPINV_END) - $(ACPINV_START) +1

# A copy of the high-mem ACPI tables
acpi.img: /dev/fmem
	sudo bash -c "./dd_hack.pl /dev/fmem acpi.img $$[$(ACPI_START)] $$[$(ACPI_LEN)]" 

acpinv.img: /dev/fmem
	sudo bash -c "./dd_hack.pl /dev/fmem acpinv.img $$[$(ACPINV_START)] $$[$(ACPINV_LEN)]"

fake.bios: fake.bios.asm
	nasm -f bin -o $@ $<
