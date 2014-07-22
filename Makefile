headers=/lib/modules/$(shell uname -r)/build

obj-m += mpauth.o

all:
	make -C $(headers) M=$(PWD) modules

clean:
	rm -f *.symvers *~ *mod.c *.o *.order *.ko *.cmd *.tmp_versions
