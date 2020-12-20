CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS = -lcrypto

N=randtest
S=$N
c=c

all: $S

$S: $S.c
	@echo "##### build randtest"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF

