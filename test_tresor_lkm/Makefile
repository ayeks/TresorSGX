target ?= test_tresor_lkm
obj-m += $(target).o


KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
	#make -C $(KDIR) M=$(PWD) modules_install
 
clean:
	make -C $(KDIR) M=$(PWD) clean
