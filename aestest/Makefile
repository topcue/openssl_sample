CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS = -lcrypto

N=aestest
S=$N
c=c

all: $S

$S: $S.c
	@echo "##### build aestest"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF

