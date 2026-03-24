obj-m += memreader.o
ccflags-y := -I$(src)/../include
CC := x86_64-linux-gnu-gcc-13

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
