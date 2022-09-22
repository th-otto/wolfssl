CC = gcc
OPT = -O2
WARN = -Wall
CFLAGS = $(OPT) $(WARN)

all: openssl

openssl:  openssl.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lcrypto -lssl

clean::
	$(RM) openssl
