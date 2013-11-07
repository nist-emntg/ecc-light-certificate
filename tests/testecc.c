#include "certificate.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"

int main(int argc, char * argv[])
{
	s_certificate cert;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	NN_DIGIT signature_r[NUMWORDS], signature_s[NUMWORDS];
	NN_DIGIT privKey[NUMWORDS];
	point_t pubKey;

	ecc_init();

	ecc_gen_private_key(privKey);
	ecc_gen_pub_key(privKey, &pubKey);

	ecdsa_init(&pubKey);

	ecdsa_sign(hash, signature_r, signature_s, privKey);

	printf("%d\n",
		   ecdsa_verify(hash, signature_r, signature_s, &pubKey)
		  );

	//generate_certificate(&cert);

	//ecdsa_init(&cert.pub_cert.pub);

	//ecdsa_sign(hash, signature_r, signature_s, cert.secret);

	//printf("%d\n",
	//       ecdsa_verify(hash, signature_r, signature_s, &cert.pub_cert.pub)
	//      );

	return 0;
}
