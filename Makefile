
KDIR ?= /usr/lib/modules/$(shell uname -r)/build

ccflags-y+= -std=gnu99 -g3 -DZL_DEBUG

obj-m += zl.o 
zl-objs := main.o nf_hooks.o memory_prot.o procfs_ops.o
all: modules

modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$(PWD) $@
