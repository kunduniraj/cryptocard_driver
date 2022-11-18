obj-m := cryptocard_mod.o
cryptocard_mod-objs := cryptocard.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

