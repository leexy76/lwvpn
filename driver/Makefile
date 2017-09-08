obj-m :=lwvpn.o
#KERNELDIR ?= /lib/modules/$(shell uname -r)/build
KERNELDIR ?= ${OCTEON_ROOT}/linux/kernel/linux
KBUILD_EXTRA_SYMBOLS=/home/leexy/Cavium_Work/new_card_0605/newcard/kernel_api/Module.symvers

PWD := $(shell pwd)

lwvpn-objs := leevpn.o leevpn_proc.o

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

#install:
#	cp ./ecard.ko ../../../test

clean:
	rm -rf *.bak *.o *~core .depend .*.cmd *.ko *.mod.c .tmp_versions
	#rm modules.order Module.symvers

