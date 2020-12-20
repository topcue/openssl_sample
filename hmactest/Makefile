CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS = -lcrypto

N=hmactest
S=$N
c=c

all: $S

$S: $S.c
	@echo "##### build hmactest"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF

