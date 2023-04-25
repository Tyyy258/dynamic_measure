obj-m := tee_agent.o  cycle.o
#lsm-objs := arm_lsm.o  sm3.o 
cycle-objs := dynamic_measure.o sm3.o
EXTRA_CFLAGS= -O2

all:
	make -C /home/ubuntu/op-tee/linux M=$(PWD) ARCH=arm64 CROSS_COMPILE=/home/ubuntu/op-tee/toolchains/aarch64/bin/aarch64-linux-gnu- modules
clean:
	make -C /home/ubuntu/op-tee/linux M=$(PWD) ARCH=arm64 CC=/home/ubuntu/op-tee/toolchains/aarch64/bin/aarch64-linux-gnu-gcc clean