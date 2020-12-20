CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS	= -lcrypto
INC		= -I.

N=hybrid_chat
S=$N_server
C=$N_client
O=aesenc

all: $S $C

%.o: %.c
	@echo "##### build object file"
	$(CC) -c $(INC) $<

$S: $S.c $O.o
	@echo "##### build server"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$C: $C.c $O.o
	@echo "##### build client"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF
