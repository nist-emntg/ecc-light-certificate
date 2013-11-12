#include "certificate.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bit.h"
#include "ecc.h"

int main(int argc, char * argv[])
{
	int i;
	char * c_str;
	s_certificate issuer;
	s_certificate wrong_issuer;
	s_certificate cert;
	s_pub_certificate cert_pub_deserialized;
	s_certificate cert_deserialized;
	s_certificate cert2;

	uint8_t array[CERT_SIZE] = { 0 };

	uint8_t ser_cert[CERT_SIZE];
	uint8_t ser_pub_cert[PUB_CERT_SIZE];

	uint8_t signature[SIG_LEN];

	s_certificate cert_path[4];
	s_pub_certificate pub_cert_path[4];

	NN_DIGIT secret[NUMWORDS], secret2[NUMWORDS];
	uint8_t point[2 * NUMBYTES], point2[2 * NUMBYTES];
	uint8_t shared_secret1[2 * NUMBYTES], shared_secret2[2 * NUMBYTES];

	/* ecc initialization */
	ecc_init();

	/* initialization */
	memset(ser_cert, 0, CERT_SIZE);
	memset(ser_pub_cert, 0, PUB_CERT_SIZE);

	/* do some bit level operation */

	generate_certificate(&issuer);
	generate_certificate(&wrong_issuer);
	generate_certificate(&cert);
	generate_certificate(&cert2);

	/* signs cert with the issuer certificate */
	sign_certificate(&issuer, &cert);
	sign_certificate(&issuer, &cert2);

	/* perform some checks on the certificate */

	assert(verify_certificate(&issuer.pub_cert, &cert.pub_cert) == 0);

	/* test against the wrong issuer */
	assert(verify_certificate(&wrong_issuer.pub_cert, &cert.pub_cert) == -1);

	/* make it so that signature verification fails */
	cert2.pub_cert.signature_r[0] ^= 0xFF;
	assert(verify_certificate(&issuer.pub_cert, &cert2.pub_cert) == -2);

	/* create a certificate path */
	for (i = 0; i < 4; i++)
	{
		generate_certificate(&cert_path[i]);
	}

	/* start signing the chain */
	sign_certificate(&issuer, &cert_path[0]);
	/* just to make sure everything worked OK */
	memcpy(&pub_cert_path[0], &cert_path[0].pub_cert, sizeof(s_pub_certificate));
	assert(verify_certificate(&issuer.pub_cert, &pub_cert_path[0]) == 0);

	for (i = 1; i < 4; i++)
	{
		sign_certificate(&cert_path[i - 1], &cert_path[i]);
		memcpy(&pub_cert_path[i], &cert_path[i].pub_cert, sizeof(s_pub_certificate));
	}

	/* verify a certificate path */
	assert(verify_certificate_path(&issuer.pub_cert, pub_cert_path, 4) == 0);

	c_str = data_to_c_array((unsigned char *)&cert, sizeof(cert), "cert");
	printf("%s\n", c_str);
	free(c_str);

	/*
	 * SERIALIZATION
	 */
	serialize_pub_cert(&cert.pub_cert, ser_pub_cert);
	c_str = data_to_c_array((unsigned char *)ser_pub_cert, sizeof(ser_pub_cert), "ser_pub_cert");
	printf("%s\n", c_str);
	free(c_str);

	serialize_cert(&cert, ser_cert);
	c_str = data_to_c_array((unsigned char *)ser_cert, sizeof(ser_cert), "ser_cert");
	printf("%s\n", c_str);
	free(c_str);

	deserialize_pub_cert(ser_pub_cert, &cert_pub_deserialized);
	assert(memcmp(&cert.pub_cert, &cert_pub_deserialized, sizeof(s_pub_certificate)) == 0);

	deserialize_cert(ser_cert, &cert_deserialized);
	assert(memcmp(&cert, &cert_deserialized, sizeof(s_certificate)) == 0);

	/**
	 * Signature tests
	 */
	certificate_ecdsa_sign(&cert,
	                       ser_cert,
	                       sizeof(ser_cert),
	                       signature);

	/* try with some valid data */
	assert(certificate_ecdsa_verify(&cert.pub_cert,
	                                ser_cert,
	                                sizeof(ser_cert),
	                                signature) == 0);
	/* try with the wrong data */
	assert(certificate_ecdsa_verify(&cert.pub_cert,
	                                array,
	                                sizeof(array),
	                                signature) < 0);
	/* try with a wrong signature */
	signature[0] ^=0xFF;
	assert(certificate_ecdsa_verify(&cert.pub_cert,
	                                ser_cert,
	                                sizeof(ser_cert),
	                                signature) < 0);


	/**
	 * ECDH tests
	 */

	/* node 1 */
	ecc_ecdh_from_host(secret, point);

	/* node 2 */
	ecc_ecdh_from_host(secret2, point2);

	/* node 1 */
	ecc_ecdh_from_network(secret, point2, shared_secret1);

	/* node 2 */
	ecc_ecdh_from_network(secret2, point, shared_secret2);

	assert(memcmp(shared_secret1, shared_secret2, NUMBYTES) == 0);

	return 0;
}
