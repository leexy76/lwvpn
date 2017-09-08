CC=gcc
CPP=g++
#CC=mips64-octeon-linux-gnu-gcc
#CPP=mips64-octeon-linux-gnu-g++

CFLAGS:=-g -DDEBUG
#CFLAGS:=-march=octeon2 -mabi=64 -O3

all: lwvpn-conf

lwvpn-conf: lwvpn-conf.o
	$(CC) $(CFLAGS) -o lwvpn-conf lwvpn-conf.o

lwvpn-conf.o: lwvpn-conf.c
	$(CC) $(CFLAGS) -c lwvpn-conf.c

clean:
	rm lwvpn-conf *.o
