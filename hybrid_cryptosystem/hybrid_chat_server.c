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

void err(char* msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

int main(int argc, char* argv[])
{
	int cnt_i;
	int serv_sock = -1;
	int clnt_sock = -1;

	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;

	APP_MSG msg_in;
	APP_MSG msg_out;

	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	byte key[AES_KEY_128] = {0x00, };
	byte iv[AES_KEY_128] = {0x00, };
	byte buffer[BUFSIZE] = {0x00, };

	int n;
	int len;
	int plaintext_len;
	int ciphertext_len;
	int publickey_len;
	int encryptedkey_len;

	BIO* bp_public = NULL;
	BIO* bp_private = NULL;
	BIO* pub = NULL;
	RSA* rsa_pubkey = NULL;
	RSA* rsa_privkey = NULL;

	// set iv
	for(cnt_i=0; cnt_i < AES_KEY_128; cnt_i++) {
		iv[cnt_i] = (byte)cnt_i;
	}

	if(argc != 2) {
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	// socket()
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1) {
		err("socket() error");
	}

	// set addr
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	// bind()
	if(bind(serv_sock, (struct sockaddr* restrict)&serv_addr, sizeof(serv_addr)) == -1) {
		err("bind() error");
	}

	// listen()
	if(listen(serv_sock, 5) == -1) {
		err("listen() error");
	}

	printf("here!!\n");
	// reading public key
	bp_public = BIO_new_file("public.pem", "r");
	if(PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL) == NULL) {
		printf("err..1\n");
		goto err;
	}
	printf("here\n");

	// reading private key
	bp_private = BIO_new_file("private.pem", "r");
	if(!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)) {
		printf("err..2\n");
		goto err;
	}
	printf("here?\n");

	while(1) {
		// accept()
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr* restrict)&clnt_addr, &clnt_addr_size);
		if(clnt_sock == -1) {
			err("accept() error");
		}

		// connetced!!
		printf("\n[TCP Server] Client connected: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));

		// setup process
		memset(&msg_in, 0, sizeof(msg_in));

		// readn() PUBLIC_KEY_REQUEST smg from client
		n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
		// ntohl info
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
		if(n == -1) {
			err("readn() error");
		} else if(n == 0) {
			err("reading EOF");
		}

		// 처음엔 반드시 PUBLIC_KEY_REQUEST이므로..
		if(msg_in.type != PUBLIC_KEY_REQUEST) {
			err("message error");
		} else {
			// sending PUBLIC_KEY
			memset(&msg_out, 0, sizeof(APP_MSG));
			msg_out.type = PUBLIC_KEY;
			msg_out.type = htonl(msg_out.type);

			pub = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPublicKey(pub, rsa_pubkey);
			publickey_len = BIO_pending(pub);	// get sizeof pub

			// pub -> msg_out.payload
			BIO_read(pub, msg_out.payload, publickey_len);
			msg_out.msg_len = htonl(publickey_len);

			// writen() to send PUBLIC_KEY 
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
			if(n == -1) {
				err("writen() error");
			}
		}

		memset(&msg_in, 0, sizeof(msg_out));

		// readn() session key from client
		n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);

		if(msg_in.type != ENCRYPTED_KEY) {
			err("message error");
		} else {
			encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload,
					buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
			memcpy(key, buffer, encryptedkey_len);
		}

		getchar();

		// data communication w/ the connected client
		while(1) {
			// readn() from client
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			printf("received message size: %d\n", n);

			if(n == -1) {
				err("readn() error");
				break;
			} else if(n == 0) {
				// recv EOF signal
				break;
			}

			// ntohl()
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);

			switch(msg_in.type) {
				case ENCRYPTED_MSG:
					// show encrypted msg
					printf("\n* encryptedMsg: \n");
					BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

					// decrypt()
					plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (byte*)plaintext);

					// show decrypted msg
					printf("* decryptedMsg:\n");
					BIO_dump_fp(stdout, (const char*)plaintext, plaintext_len);
					break;
				default:
					break;
			}

			// print the received message
			plaintext[plaintext_len] = '\0';
			printf("\n[*] %s\n", plaintext);

			// input a message that you want to send
			printf("Input a message > \n");
			if(fgets(plaintext, BUFSIZE+1, stdin) == NULL) {
				break;
			}

			// removing '\n'
			len = strlen(plaintext);
			if(plaintext[len-1] == '\n') {
				plaintext[len-1] = '\0';
			}
			if(strlen(plaintext) == 0) {
				break;
			}

			msg_out.type = ENCRYPTED_MSG;
			msg_out.type = htonl(msg_out.type);

			// encrypt()
			ciphertext_len = encrypt((byte*)plaintext, len, key, iv, msg_out.payload);
			msg_out.msg_len = htonl(ciphertext_len);

			// writen() to client
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
			if(n == -1) {
				err("writen() error");
				break;
			}
		}
		// close()
		close(clnt_sock);
		printf("[TCP Server] Client close: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
	}

	// err label
err:
	// close()
	close(serv_sock);
	return 0;
}

// EOF
