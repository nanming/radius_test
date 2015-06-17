
all:
	gcc -o radius radius.c radius-md5.c md5.h md5.c -lpthread
clean:
	rm radius -rf
