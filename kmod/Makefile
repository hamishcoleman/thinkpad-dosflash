KERNEL_SRC_DIR = /lib/modules/`uname -r`/build

obj-m += dosflash.o
dosflash-objs := main.o 

all:	clean dosflash

dosflash : clean
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules

clean : 
	rm -f *.o *.ko \
		Module.symvers Module.markers modules.order \
		*.mod.c .*.o.cmd .*.ko.cmd .*.o.d
	rm -rf .tmp_versions
