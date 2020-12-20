CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS = -lcrypto

N=rsaestest
S=$N
c=c

all: $S

$S: $S.c
	@echo "##### build rsatest"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF

