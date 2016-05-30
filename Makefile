#
# Reverse engineer the thinkpad dosflash utility
#
# Copyright (C) 2016 Hamish Coleman
#

all:
	$(info See README file for additional details)
	false

.PHONY: all

#
# Radare didnt seem to let me specify the directory to store the project file,
# so this target hacks around that
#
install.radare.projects:
	mkdir -p ~/.config/radare2/projects/thinkpad.dosflash.d
	cp -fs $(PWD)/radare/thinkpad.dosflash ~/.config/radare2/projects


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

