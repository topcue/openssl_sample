#ifndef __AESENC_H__
#define __AESENC_H__

typedef unsigned char byte;

extern void handleErrors(void);
extern int encrypt(byte* plaintext, int plaintext_len, byte* key, byte* iv, byte* ciphertext);
extern int decrypt(byte* ciphertext, int ciphertext_len, byte* key, byte* iv, byte* recovered);

#endif

// EOF
