#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

typedef unsigned char byte;

void err(char* msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

int main(int argc, char* argv[])
{
	int cnt_i;
	int sock = -1;
	struct sockaddr_in serv_addr;
	int len;

	APP_MSG msg_in;
	APP_MSG msg_out;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };

	byte key[AES_KEY_128] = {0x00, };
	byte iv[AES_KEY_128] = {0x00, };
	byte encrypted_key[BUFSIZE] = {0x00, };

	BIO* rpub = NULL;
	BIO* rsa_pubkey = NULL;

	int n;
	int plaintext_len;
	int ciphertext_len;

	// gen random session key
	RAND_poll();
	RAND_bytes(key, sizeof(key));

	// set iv
	for(cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++) {
		iv[cnt_i] = (byte)cnt_i;
	}

	if(argc != 3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	// socket()
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		err("socket() error");
	}

	// set addr
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	// connect()
	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		err("connect() error");
	}

	// setup process
	// sending PUBLIC_KEY_REQUEST msg
	memset(&msg_out, 0, sizeof(APP_MSG));
	msg_out.type = PUBLIC_KEY_REQUEST;
	// htonl() info
	msg_out.type = htonl(msg_out.type);

	// writen() to send PUBLIC_KEY_REQUEST
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n == -1) {
		err("writen() error");
	}

	// receiving PUBLIC_KEY msg
	memset(&msg_in, 0, sizeof(APP_MSG));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	// ntohl info
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
	if(n == -1) {
		err("readn() error");
	} else if(n == 0) {
		err("reading EOF");
	}

	if(msg_in.type != PUBLIC_KEY) {
		// recv wrong type
		err("message error");
	} else {
		// show recv (public key)
		BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

		// extract pubkey
		rpub = BIO_new_mem_buf(msg_in.payload, -1);
		// write at rpub
		BIO_write(rpub, msg_in.payload, msg_in.msg_len);
		if(!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)) {
			err("PEM_read_bio_RSAPublicKey() error");
		}
	}

	// sending ENCRYPTED_KEY msg
	memset(&msg_out, 0, sizeof(APP_MSG));
	msg_out.type = ENCRYPTED_KEY;
	msg_out.type = htonl(msg_out.type);

	// encrypt random session key
	msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload,
			rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
	msg_out.msg_len = htonl(msg_out.msg_len);

	// writen() to send encrypted session key to server
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n == -1) {
		err("writen() error");
	}

	getchar();

	while(1) {
		// input a message
		printf("Input a message >\n");
		if (fgets(plaintext, BUFSIZE+1, stdin) == NULL) {
			break;
		}

		// removing '\n' (since fgets())
		len = strlen(plaintext);
		if(plaintext[len-1] == '\n') {
			plaintext[len-1] = '\0';
		}
		if(strlen(plaintext) == 0) {
			break;
		}

		memset(&msg_out, 0, sizeof(msg_out));
		msg_out.type = ENCRYPTED_MSG;
		msg_out.type = htonl(msg_out.type);

		// encrypt()
		ciphertext_len = encrypt((byte*)plaintext, len, key, iv, msg_out.payload);
		msg_out.msg_len = htonl(ciphertext_len);

		// writen() to server
		n = writen(sock, &msg_out, sizeof(APP_MSG));
		if(n == -1) {
			err("writen() error");
			break;
		}

		// readn() from server
		n = readn(sock, &msg_in, sizeof(APP_MSG));
		printf("received message size: %d\n", n);
		if(n == -1) {
			err("readn() error");
			break;
		} else if(n == 0) {
			break;
		}

		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);

		switch(msg_in.type) {
			case ENCRYPTED_MSG:
				// show encrypted msg
				printf("\n* encryptedMsg:\n");
				BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

				// decrypt()
				plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (byte*)plaintext);

				// show decrypted msg
				printf("\n* decryptedMsg:\n");
				BIO_dump_fp(stdout, (const char*)plaintext, plaintext_len);
				break;
			default:
				break;
		}        

		// print the received message
		plaintext[plaintext_len] = '\0';
		printf("[*] %s\n", plaintext);
	}

	// close()
	close(sock);
	return 0;
}


// EOF
