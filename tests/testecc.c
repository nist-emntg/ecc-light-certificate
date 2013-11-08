#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"
#include "ecdsa.h"
#include "ecc.h"

int main(int argc, char * argv[])
{
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	NN_DIGIT signature_r[NUMWORDS], signature_s[NUMWORDS];
	NN_DIGIT privKey[NUMWORDS];
	point_t pubKey;
	uint8_t data [52] = {
		1, 2, 3, 4, 5
	};
	SHA256_CTX ctx;

	memset(privKey, 0, NUMBYTES);
	memset(&pubKey, 0, sizeof(pubKey));
	memset(signature_r, 0, NUMBYTES);
	memset(signature_s, 0, NUMBYTES);


	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, 52);
	SHA256_Final(hash, &ctx);

	ecc_init();

	ecc_gen_private_key(privKey);
	ecc_gen_pub_key(privKey, &pubKey);

	ecdsa_init(&pubKey);

	ecdsa_sign(hash, signature_r, signature_s, privKey);

	assert(ecdsa_verify(hash, signature_r, signature_s, &pubKey) == 1);

	signature_r[0] ^= 0xff;

	assert(ecdsa_verify(hash, signature_r, signature_s, &pubKey) != 1);

	return 0;
}
