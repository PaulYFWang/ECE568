CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := sslhelpers.c client.c server.c 
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)


client: client.o
	$(CC) $(LDFLAGS) -o client client.o sslhelpers.o

server: server.o
	$(CC) $(LDFLAGS) -o server server.o sslhelpers.o

client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sslhelpers.o: sslhelpers.c
	$(CC) $(CFLAGS) -c -o sslhelpers.o  sslhelpers.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

