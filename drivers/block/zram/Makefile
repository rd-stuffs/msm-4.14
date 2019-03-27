ccflags-y += -mllvm -inline-threshold=15000
ccflags-y += -mllvm -inlinehint-threshold=10000
ccflags-y += -Ofast

zram-y				:=	zcomp.o zram_drv.o zram_dedup.o
obj-$(CONFIG_ZRAM)	+=	zram.o
