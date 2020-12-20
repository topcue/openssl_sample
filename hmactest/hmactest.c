#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

typedef unsigned char byte;

void print_it(const char* label, const byte* buff, size_t len);
void hmac_simple_test();
int sign_it(const byte* msg, size_t mlen, byte** sig, size_t *slen, EVP_PKEY* pkey);
int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey);

int main(int argc, char* argv[])
{
	printf("Testing HAMC functions with EVP_DigestSign\n");
	OpenSSL_add_all_algorithms();
	hmac_simple_test ();
	return 0;
}

void print_it(const char* label, const byte* buff, size_t len)
{
	if(!buff || !len) {
		return;
	}
	if(label) {
		printf("%s: ", label);
	}
	for(size_t i = 0; i < len; ++i) {
		printf("%02X", buff[i]);

	}
	printf("\n");
}

void hmac_simple_test()
{
	/* Sign and Verify HMAC keys */
	EVP_PKEY *hmacKey = NULL;
	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	byte hkey[EVP_MAX_MD_SIZE] = {0x00, };
	int size = EVP_MD_size(md);
	int ret;

	// const byte msg[] = "Now is the time for all good men to come to the aide of their country";
	byte* msg = NULL;
	msg = (byte*)malloc(sizeof(msg)*2000);

	byte* sig = NULL;
	size_t slen = 0;

	// hmac key generation
	ret = RAND_bytes(hkey, size);
	assert(ret == 1);

	hmacKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, size);
	assert(hmacKey != NULL);

	OPENSSL_cleanse(hkey, sizeof(hkey));
	
	// sign
	ret = sign_it(msg, sizeof(msg), &sig, &slen, hmacKey);
	
	assert(ret == 0);

	if(ret == 0) {
		printf("Created signature\n");
	} else {
		printf("Failed to create signature, return code %d\n", ret);
		exit(1); /* Should cleanup here */
	}

	print_it("Signature", sig, slen);

	// verify
	ret = verify_it(msg, sizeof(msg), sig, slen, hmacKey);
	if(ret == 0) {
		printf("Verified signature\n");
	} else {
		printf("Failed to verify signature, return code %d\n", ret);
	}

	if(sig){
		OPENSSL_free(sig);
	}
	if(hmacKey){
		EVP_PKEY_free(hmacKey);
	}
}

int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
	/* Returned to caller */
	int result = -1;
	size_t req = 0;
	EVP_MD_CTX* ctx = NULL;
	*sig = NULL;

	ctx = EVP_MD_CTX_create();
	if(ctx == NULL) {
		printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	if (md == NULL) {
		printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	int rc = EVP_DigestInit_ex(ctx, md, NULL);
	if(rc != 1){
		printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc= EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
	if(rc!=1){
		printf("Evp_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, mlen);
	if(rc != 1){
		printf("EvP_DigestSignUpdate failed, error Ox%lx\n", ERR_get_error());
		return result;
	}
	rc = EVP_DigestSignFinal(ctx, NULL, &req);
	if(rc!=1){
		printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
		return result;
	}
	
	*sig = OPENSSL_malloc(req);
	if(*sig == NULL){
		printf("OPENSSL_malloc failed error, 0x%lx", ERR_get_error());
		return result;
	}
	*slen = req;
	rc = EVP_DigestSignFinal(ctx, *sig, slen);
	if(rc!=1){
		printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
		return result;
	}

	result = 0;
	if(ctx){
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
	/*Returned to caller */
	int result = -1;

	EVP_MD_CTX* ctx = NULL;

	ctx = EVP_MD_CTX_create();
	if(ctx == NULL){
		printf("EVP_MD_cTX_create failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	if(md == NULL) {
		printf("EVP_get_digestbyname failed error 0x%lx\n", ERR_get_error());
		return result;
	}

	int rc = EVP_DigestInit_ex(ctx, md, NULL);
	if(rc != 1) {
		printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
	if(rc!=1){
		printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, mlen);
	if(rc!=1){
		printf("EvP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	byte buffer[EVP_MAX_MD_SIZE];
	size_t size = sizeof(buffer);

	rc = EVP_DigestSignFinal(ctx, buffer, &size);
	if(rc != 1){
		printf("EvP_DigestSignFinal failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const size_t m = (slen < size ? slen : size);
	result = CRYPTO_memcmp(sig, buffer, m);

	OPENSSL_cleanse(buffer, sizeof(buffer));

	if(ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return result;

}

// EOF

