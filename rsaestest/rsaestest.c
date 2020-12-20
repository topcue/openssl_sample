#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

static int _pad_unknown(void);
int rsaes_simple_test(void);
int rsaes_simple_test2(void);
int rsaes_evp_test(void);

int main()
{
	rsaes_simple_test();	// write
	rsaes_simple_test2();	// read
	
	rsaes_evp_test();

	return 0;
}

static int _pad_unknown(void)
{
	unsigned long l;
	while((l = ERR_get_error()) != 0) {
		if(ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE) {
			return (1);
		}
	}
	return 0;
}

int rsaes_simple_test()
{
	int ret = 1;
	RSA* rsa;
	unsigned char ptext[256] = {0x00, };
	unsigned char ctext[256] = {0x00, };
	unsigned char ptext_ex[] = "Hello, world!!";
	unsigned char ctext_ex[256] = {0x00, };
	int plen = sizeof(ptext_ex)-1;
	int clen = 0;
	int num;
	BIO* bp_public = NULL;
	BIO* bp_private = NULL;
	unsigned long e_value = RSA_F4;
	BIGNUM* exponent_e = BN_new();

	rsa = RSA_new();

	BN_set_word(exponent_e, e_value);

	// RSA key gen
	if(RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == NULL) {
		fprintf(stderr, "RSA_generate_key_ex() error");
		ret = -1;
		goto err;
	}

	// write "public.pem"
	bp_public = BIO_new_file("public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
	if(ret != 1) {
		goto err;
	}

	// write "private.pem"
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
	if(ret != 1) {
		goto err;
	}

	// show plaintext
	printf("\nplaintext\n");
	BIO_dump_fp(stdout, (const char*)ptext_ex, plen);

	// encrypt
	num = RSA_public_encrypt(plen, ptext_ex, ctext, rsa, RSA_PKCS1_OAEP_PADDING);
	if(num == -1 && _pad_unknown()) {
		fprintf(stderr, "No OAEP support\n");
		ret = -1;
		goto err;
	}

	// show ciphertext
	printf("\nciphertext\n");
	BIO_dump_fp(stdout, (const char*)ctext, num);

	// decrypt
	num = RSA_private_decrypt(num, ctext, ptext, rsa, RSA_PKCS1_OAEP_PADDING);
	if(num == plen && memcmp(ptext, ptext_ex, num) != 0) {
		fprintf(stderr, "OAEP decryption (encrypted data) failed!\n");
		ret = -1;
		goto err;
	}

	// show recovered
	printf("\nrecovered\n");
	BIO_dump_fp(stdout, (const char*)ptext, num);

// error label
err:
	RSA_free(rsa);
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);

	return ret;
}

int rsaes_simple_test2(void)
{
    int ret = 1;

    BIO* bp_public = NULL;
    BIO* bp_private = NULL;
    RSA* rsa_pubkey = NULL;
    RSA* rsa_privkey = NULL;

    unsigned char ptext[256] = {0x00, };
    unsigned char ctext[256] = {0x00, };
    unsigned char ptext_ex[] = "Hello, world!!";
    unsigned char ctext_ex[256] = {0x00, };
    int plen = sizeof(ptext_ex)-1;
    int clen = 0;
    int num;

    bp_public = BIO_new_file("public.pem", "r");
    if(PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL) == NULL) {
        goto err;
    }
	
    bp_private = BIO_new_file("private.pem", "r");
    if(PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL) == NULL) {
        goto err;
    }

    printf("\nplaintext\n");
    BIO_dump_fp(stdout, (const char*)ptext_ex, plen);

    num = RSA_public_encrypt(plen, ptext_ex, ctext, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
    
    if(num == -1 && _pad_unknown()) {
        fprintf(stderr, "No OAEP support\n");
        ret = -1;
        goto err;
    }

    printf("\nciphertext\n");
    BIO_dump_fp(stdout, (const char*)ctext, num);

    num = RSA_private_decrypt(num, ctext, ptext, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
    
    if(num != plen || memcmp(ptext, ptext_ex, num) != 0) {
        fprintf(stderr, "OAEP_decryption(encrypted data) failed\n");
        ret = -1;
        goto err;
    }

    printf("\nrecovered\n");
    BIO_dump_fp(stdout, (const char*)ptext, num);

err:
    if(bp_public) {
        BIO_free(bp_public);    
    }
    if(bp_private) {
        BIO_free(bp_private);    
    }

    return ret;
}


int rsaes_evp_test(void)
{
    RSA* rsa = NULL;
    EVP_PKEY* pubkey = NULL;
    EVP_PKEY* privkey = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    int ret;
    int rc;
    BIO* out = NULL;

    unsigned char msg[] = "Hello, world!";
    unsigned char* plaintext = msg;
    unsigned char* ciphertext = NULL;
    unsigned char* recovered = NULL;
    size_t outlen;
    size_t inlen;

    unsigned long e_value = RSA_F4;
    BIGNUM* exponent_e = BN_new();

    // allocate BIO for "stdout"
    out = BIO_new_fp(stdout, BIO_CLOSE);
    inlen = sizeof(msg);

    // alloc pubkey
    pubkey = EVP_PKEY_new();
    assert(pubkey != NULL);

	// alloc privkey
    privkey = EVP_PKEY_new();
    assert(privkey != NULL);

	// alloc RSA struct
    rsa = RSA_new();

    BN_set_word(exponent_e, e_value);

	// gen RSA key pair
    if(RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == 0) {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }

	// assign privkey
    ret = EVP_PKEY_assign_RSA(privkey, RSAPrivateKey_dup(rsa));
    assert(ret == 1);

	// alloc pubkey
    ret = EVP_PKEY_assign_RSA(pubkey, RSAPublicKey_dup(rsa));
    assert(ret == 1);

	// show key pair
	printf("[*] show key pair info\n");
    EVP_PKEY_print_private(out, privkey, 0, NULL);
    EVP_PKEY_print_public(out, pubkey, 0, NULL);

    if(rsa) {
        RSA_free(rsa);
    }

	/// RSA encryption!

	// alloc EVP_CTX w/ pubkey
    ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    assert(ctx != NULL);

    if(EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init() error\n");
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding() error");
    }

	// show plaintext
    printf("\nplaintext\n");
    BIO_dump_fp (stdout, (const char *)plaintext, inlen);

    // get ciphertext size (2nd param -> NULL)
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, inlen) <= 0){
        fprintf(stderr, "EVP_PKEY_encrypt() 1 error\n");
    }
    
	// alloc ciphertext mem
    ciphertext = OPENSSL_malloc(outlen);
    assert(ciphertext != NULL);
    memset (ciphertext, 0, outlen);
    
	// encrypt (2nd param -> ciphertext)
    if ((ret = EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, inlen)) <= 0){
        fprintf(stderr, "EVP_PKEY_encrypt() 2 error: %d\n", ret);
    }
    
	// show ciphertext
    printf("\nciphertext\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, outlen);
    
    EVP_PKEY_CTX_free(ctx);
    
    /// RSA decryption!!

	// alloc EVP_CTX w/ privkey
    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    assert(ctx != NULL);
 
    if (EVP_PKEY_decrypt_init(ctx) <= 0){
        fprintf(stderr, "EVP_PKEY_decrypt_init() error\n");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING ) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding() error\n");
    }

    inlen = outlen;

	// get recovered size (2nd param -> NULL)
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, inlen) <= 0){
        fprintf(stderr, "EVP_PKEY_decrypt() 1 error\n");
    }
    
	// alloc recovered mem
    recovered = OPENSSL_malloc(outlen);
    assert(recovered != NULL);
    memset(recovered, 0, outlen);

	// decrypt (2nd param -> recovered)
    if ((ret = EVP_PKEY_decrypt(ctx, recovered, &outlen, ciphertext, inlen)) <= 0){
        fprintf(stderr, "EVP_PKEY_encrypt() 2 error: %d\n", ret);
    }

	// show recovered
    printf("\nrecovered\n");
    BIO_dump_fp (stdout, (const char *)recovered, outlen);

    EVP_PKEY_CTX_free(ctx);

err:
    if(ciphertext) {
        OPENSSL_free(ciphertext);
    }
    if(recovered) {
        OPENSSL_free(recovered);
    }

    return ret;
}


// EOF
