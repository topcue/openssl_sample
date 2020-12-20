#include "aesenc.h"

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(byte* plaintext, int plaintext_len, byte* key, byte* iv, byte* ciphertext)
{
	EVP_CIPHER_CTX* ctx = NULL;
	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
		handleErrors();   
	}

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		handleErrors();
	}
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal(ctx, ciphertext+len, &len)) {
		handleErrors();
	}
	
	ciphertext_len += len;

	if(ctx != NULL) {
		EVP_CIPHER_CTX_free(ctx);
	}

	return ciphertext_len;
}


int decrypt(byte* ciphertext, int ciphertext_len, byte* key, byte* iv, byte* recovered)
{
	EVP_CIPHER_CTX* ctx = NULL;
	int len;
	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
		handleErrors();
	}
	if(1 != EVP_DecryptUpdate(ctx, recovered, &len, ciphertext, ciphertext_len)) {
		handleErrors();
	}
	plaintext_len = len;
	if(1 != EVP_DecryptFinal(ctx, recovered+len, &len)) {
		handleErrors();
	}
	plaintext_len += len;

	if(ctx != NULL) {
		EVP_CIPHER_CTX_free(ctx);
	}

	return plaintext_len;
}

// EOF
