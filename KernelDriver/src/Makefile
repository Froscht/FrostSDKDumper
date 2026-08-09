obj-m += memreader.o
ccflags-y := -I$(src)/../include
# No CC pin — Kbuild must use the same compiler the running kernel was built
# with (7.0.0-28-generic: gcc 15.2.0). The old x86_64-linux-gnu-gcc-13 pin was
# for an earlier kernel and now breaks the build outright.

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
