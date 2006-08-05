PAM_LIB_DIR = $(DESTDIR)/lib/security
CC = gcc
LD = ld
INSTALL = /usr/bin/install
CFLAGS = -fPIC -O2 -c -g -Wall -Wformat-security -fno-strict-aliasing
LDFLAGS = -x --shared 
PAMLIB = -lpam
CPPFLAGS =

all: pam_encfs.so

pam_encfs.so: pam_encfs.o
	$(LD) $(LDFLAGS) -o pam_encfs.so pam_encfs.o $(PAMLIB)

pam_encfs.o: pam_encfs.c
	$(CC) $(CFLAGS) pam_encfs.c

install: pam_encfs.so
	$(INSTALL) -m 0755 -d $(PAM_LIB_DIR)
	$(INSTALL) -m 0644 pam_encfs.so $(PAM_LIB_DIR)

clean:
	rm -f pam_encfs.o pam_encfs.so

spotless:
	rm -f pam_encfs.so pam_encfs.o *~ core
