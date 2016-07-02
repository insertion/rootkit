obj-m += rt.o
obj-m += rt_sys_call.o
obj_m += hidels.o
obj_m += hideps.o
obj_m += hidens.o
KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
