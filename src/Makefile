# program name
PROJECT=p11d

# version number
VERSION=0

# define the operational mode:
# DISABLED   turns off the protection mechanism,
# PERMISSIVE raises warning about potentially dangerous operations,
# ENFORCE    prevents attacks to succeed [TODO]
MODE=PERMISSIVE

# compiler and linker options
CC=gcc
CFLAGS=--std=c99 -Wall -Wextra -O2 -I. -D"MODE=${MODE}"
LDFLAGS=-L/usr/local/lib/caml-crush -lp11clientfoo
# LDFLAGS=-L/usr/lib/opencryptoki -lopencryptoki

default: all

all: p11d test_attacks

test_attacks: test_attacks.c utils.c attacks.c
	$(CC) -o test_attacks test_attacks.c utils.c attacks.c ${LDFLAGS} ${CFLAGS} -pedantic

p11d: utils.c
	$(CC) -shared -fPIC utils.c p11d.c -o p11d.so -ldl ${LDFLAGS} ${CFLAGS}

test_digest: test_digest.c utils.c
	$(CC) -o test_digest test_digest.c utils.c ${LDFLAGS} ${CFLAGS} -pedantic

.PHONY: default all
