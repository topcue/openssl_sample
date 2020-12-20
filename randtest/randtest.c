#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int main(int argc, char* argv[])
{
	unsigned char key[16] = {0x00, };
	int ret = 1;
	int cnt_i = 0;

	RAND_poll();

	for (cnt_i = 0; cnt_i < 10; cnt_i++)  {
		ret = RAND_bytes(key, sizeof(key));
		if(ret <= 0) {
			fprintf(stderr, "RAND_bytes() error");
			return 0;
		}

		printf("Key:\n");
		BIO_dump_fp(stdout, (const char*)key, sizeof(key));
	}

	RAND_cleanup();

	return 0;
}

// EOF
