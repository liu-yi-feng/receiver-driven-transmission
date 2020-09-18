obj-m := seadp.o
seadp-objs := main.o congestion.o
PWD := $(shell pwd)
KVER := $(shell uname -r)
KDIR := /lib/modules/${KVER}/build/

all:
	${MAKE} -C ${KDIR} M=${PWD} modules

clean:
#rm -rf *.o *.mod.c *.mod.o *.ko *.symvers *.order *.a
	${MAKE} -C ${KDIR} M=${PWD} modules clean
