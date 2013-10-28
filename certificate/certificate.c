#include "certificate.h"
#include "bit.h"
#include "prng.h"

#include <string.h>

#ifndef WITH_CONTIKI
#include <stdio.h>
#endif

#define C_STR_SIZE 4096

int generate_certificate(s_certificate *out_cert)
{
	memset(out_cert, 0, sizeof(* out_cert));

	do {
		prng((unsigned char *)out_cert->secret, sizeof(uint32_t) * arrayLength);
	} while (!ecc_is_valid_key(out_cert->secret));

	ecc_gen_pub_key(out_cert->secret,
	                out_cert->pub_cert.pub_x,
	                out_cert->pub_cert.pub_y);

	return 0;
}


/* return 0 if the certificate is valid, -1 or -2 otherwise */
int verify_certificate(s_pub_certificate * signer_cert,
                       s_pub_certificate * certificate)
{
	SHA256_CTX c256;
	char hash[SHA256_DIGEST_LENGTH];
	/* fix the endianness */
	uint8_t pub_x[32], pub_y[32];
	uint32_array_to_uint8_be(signer_cert->pub_x, 32, pub_x);
	uint32_array_to_uint8_be(signer_cert->pub_y, 32, pub_y);

	memset(hash, 0, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, 32);
	SHA256_Update(&c256, pub_y, 32);
	SHA256_Update(&c256, (unsigned char*)signer_cert->issuer,
	              sizeof(signer_cert->issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	if (memcmp(hash, certificate->issuer, SHA256_DIGEST_LENGTH)) {
		return -1; /* trusted certificate does not match the issuer certificate */
	}

	uint32_array_to_uint8_be(certificate->pub_x, 32, pub_x);
	uint32_array_to_uint8_be(certificate->pub_y, 32, pub_y);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, 32);
	SHA256_Update(&c256, pub_y, 32);
	SHA256_Update(&c256, (unsigned char*)certificate->issuer,
	              sizeof(certificate->issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	if (ecc_ecdsa_validate((uint32_t *) signer_cert->pub_x,
	                       (uint32_t *) signer_cert->pub_y,
	                       (uint32_t *) hash,
	                       (uint32_t *) certificate->signature_r,
	                       (uint32_t *) certificate->signature_s)
	   ) {
		return -2; /* certificate signature is invalid */
	}

	return 0;
}

int verify_certificate_path(s_pub_certificate * cert_authority,
                            s_pub_certificate cert_path[],
                            uint8_t path_length)
{

	s_pub_certificate * prev_cert, * cert;
	int ret;

	/* go through all the certificate in the path */
	for (prev_cert = cert_authority, cert = cert_path;
	     path_length;
	     prev_cert = cert, cert++, path_length--) {
		ret = verify_certificate(prev_cert, cert);
		if (ret)
			return ret;
	}

	return 0;
}

int serialize_pub_cert(s_pub_certificate * src, uint8_t dst[PUB_CERT_SIZE])
{
	uint32_array_to_uint8_be(src->pub_x, 32, dst);
	uint32_array_to_uint8_be(src->pub_y, 32, dst + 32);
	memcpy(dst + 64, src->issuer, SHA256_DIGEST_LENGTH);
	uint32_array_to_uint8_be(src->signature_r, 36, dst + 64 + SHA256_DIGEST_LENGTH);
	uint32_array_to_uint8_be(src->signature_s, 36, dst + 100 + SHA256_DIGEST_LENGTH);

	return 0;
}

int serialize_cert(s_certificate * src, uint8_t dst[CERT_SIZE])
{
	uint32_array_to_uint8_be(src->pub_cert.pub_x, 32, dst);
	uint32_array_to_uint8_be(src->pub_cert.pub_y, 32, dst + 32);
	memcpy(dst + 64, src->pub_cert.issuer, SHA256_DIGEST_LENGTH);
	uint32_array_to_uint8_be(src->pub_cert.signature_r, 36, dst + 64 + SHA256_DIGEST_LENGTH);
	uint32_array_to_uint8_be(src->pub_cert.signature_s, 36, dst + 100 + SHA256_DIGEST_LENGTH);
	uint32_array_to_uint8_be(src->secret, 32, dst + 136 + SHA256_DIGEST_LENGTH);

	return 0;
}

int deserialize_pub_cert(uint8_t * src, s_pub_certificate * dst)
{
	uint8be_array_to_uint32_host(src, 32, dst->pub_x);
	uint8be_array_to_uint32_host(src + 32, 32, dst->pub_y);
	memcpy(dst->issuer, src + 64, SHA256_DIGEST_LENGTH);
	uint8be_array_to_uint32_host(src + 64 + SHA256_DIGEST_LENGTH, 36, dst->signature_r);
	uint8be_array_to_uint32_host(src + 100 + SHA256_DIGEST_LENGTH, 36, dst->signature_s);
	return 0;
}

int deserialize_cert(uint8_t * src, s_certificate * dst)
{
	uint8be_array_to_uint32_host(src, 32, dst->pub_cert.pub_x);
	uint8be_array_to_uint32_host(src + 32, 32, dst->pub_cert.pub_y);
	memcpy(dst->pub_cert.issuer, src + 64, SHA256_DIGEST_LENGTH);
	uint8be_array_to_uint32_host(src + 64 + SHA256_DIGEST_LENGTH, 36, dst->pub_cert.signature_r);
	uint8be_array_to_uint32_host(src + 100 + SHA256_DIGEST_LENGTH, 36, dst->pub_cert.signature_s);
	uint8be_array_to_uint32_host(src + 136 + SHA256_DIGEST_LENGTH, 32, dst->secret);
	return 0;
}

int certificate_ecdsa_sign(s_certificate * certificate,
                           const uint8_t * data,
                           int length,
                           uint8_t * signature)
{
	SHA256_CTX c256;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	unsigned char random[32];
	uint32_t signature_r[9];
	uint32_t signature_s[9];

	SHA256_Init(&c256);
	SHA256_Update(&c256, data, length);
	SHA256_Final(hash, &c256);

	memset(signature_r, 0, 9 * sizeof(uint32_t));
	memset(signature_s, 0, 9 * sizeof(uint32_t));


	/* sign the hash */
	prng(random, sizeof(random));
	while (ecc_ecdsa_sign((uint32_t *) certificate->secret,
	                      (uint32_t *) hash,
	                      (uint32_t *) random,
	                      (uint32_t *) signature_r,
	                      (uint32_t *) signature_s)) {
		prng(random, sizeof(random));
	}

	/* convert the fields to the proper endianness */
	uint32_array_to_uint8_be(signature_r, 9 * sizeof(uint32_t), signature);
	uint32_array_to_uint8_be(signature_s,
	                         9 * sizeof(uint32_t),
	                         signature + 9 * sizeof(uint32_t));

	return 0;
}

int certificate_ecdsa_verify(s_pub_certificate * certificate,
                             const uint8_t * data,
                             int length,
                             uint8_t * signature)
{
	SHA256_CTX c256;
	char hash[SHA256_DIGEST_LENGTH];
	/* fix the endianness */
	uint32_t signature_r[9], signature_s[9];

	uint8be_array_to_uint32_host(signature, 9 * sizeof(uint32_t), signature_r);
	uint8be_array_to_uint32_host(signature + 9 * sizeof(uint32_t),
	                             9 * sizeof(uint32_t),
	                             signature_s);

	memset(hash, 0, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c256);
	SHA256_Update(&c256, data, length);
	SHA256_Final((uint8_t *) hash, &c256);

	if (ecc_ecdsa_validate((uint32_t *) certificate->pub_x,
	                       (uint32_t *) certificate->pub_y,
	                       (uint32_t *) hash,
	                       (uint32_t *) signature_r,
	                       (uint32_t *) signature_s)
	   ) {
		return -1; /* signature is invalid */
	}

	return 0;

}

int ecc_ecdh_from_host(uint8_t secret[32],
                       uint8_t point[POINT_SIZE])
{
	uint32_t result_x[8], result_y[8];

	prng(secret, sizeof(secret));

	ecc_ec_mult(ecc_g_point_x,
	            ecc_g_point_y,
	            (uint32_t *) secret,
	            result_x,
	            result_y);
	uint32_array_to_uint8_be(result_x, 32, point);
	uint32_array_to_uint8_be(result_y, 32, &point[32]);

	return 0;
}

int ecc_ecdh_from_network(uint8_t secret[32],
                          uint8_t point[POINT_SIZE],
                          uint8_t shared_secret[POINT_SIZE])
{

	uint32_t pub_x[8], pub_y[8], result_x[8], result_y[8];

	uint8be_array_to_uint32_host(point, 32, pub_x);
	uint8be_array_to_uint32_host(&point[32], 32, pub_y);

	ecc_ec_mult(pub_x,
	            pub_y,
	            (uint32_t *) secret,
	            result_x,
	            result_y);

	uint32_array_to_uint8_be(result_x, 32, shared_secret);
	uint32_array_to_uint8_be(result_y, 32, &shared_secret[32]);

	return 0;
}

int ecc_ecdh_derive_key(uint8_t shared_secret[POINT_SIZE],  uint8_t key[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX c256;

	SHA256_Init(&c256);
	SHA256_Update(&c256, shared_secret, POINT_SIZE);
	SHA256_Final(key, &c256);

	return 0;
}

#ifndef WITH_CONTIKI
#include <string.h>
void sign_certificate(s_certificate * signing_party,
                      s_certificate * certificate)
{
	unsigned char random[32];
	uint8_t pub_x[32], pub_y[32];
	SHA256_CTX c256;
	char hash[SHA256_DIGEST_LENGTH];

	/* convert the fields to the proper endianness */
	uint32_array_to_uint8_be(signing_party->pub_cert.pub_x, 32, pub_x);
	uint32_array_to_uint8_be(signing_party->pub_cert.pub_y, 32, pub_y);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, 32);
	SHA256_Update(&c256, pub_y, 32);
	SHA256_Update(&c256, (unsigned char*)signing_party->pub_cert.issuer,
	              sizeof(signing_party->pub_cert.issuer));
	SHA256_Final((uint8_t *) certificate->pub_cert.issuer, &c256);

	memset(certificate->pub_cert.signature_r, 0, 36);
	memset(certificate->pub_cert.signature_s, 0, 36);

	/* convert the fields to the proper endianness */
	uint32_array_to_uint8_be(certificate->pub_cert.pub_x, 32, pub_x);
	uint32_array_to_uint8_be(certificate->pub_cert.pub_y, 32, pub_y);

	/* compute hash first on the certificate whose signature fields are zeroed out */
	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, 32);
	SHA256_Update(&c256, pub_y, 32);
	SHA256_Update(&c256, (unsigned char*)certificate->pub_cert.issuer,
	              sizeof(certificate->pub_cert.issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	/* sign the hash */
	prng(random, sizeof(random));
	while (ecc_ecdsa_sign((uint32_t *) signing_party->secret,
	                      (uint32_t *)    hash,
	                      (uint32_t *) random,
	                      (uint32_t *)certificate->pub_cert.signature_r,
	                      (uint32_t *)certificate->pub_cert.signature_s)) {
		prng(random, sizeof(random));
	}
}

/* returns a C string contains the encoding of data in a C array
 * (this string must be free'd) */
char * data_to_c_array(uint8_t * data, int datalen, char * dataname)
{
	int numchar, offset = 0;
	char * array_str = malloc(C_STR_SIZE); /* arbitrary big */
	numchar = snprintf(array_str, C_STR_SIZE, "uint8_t %s [%u] = {", dataname, datalen);
	offset = numchar;

	for (; datalen > 1; datalen--) {
		numchar = snprintf(array_str + offset, C_STR_SIZE - offset, "0x%.2X, ", *data++);
		offset += numchar;
	}

	/* last byte of data does not have a comma afterwards and needs to be
	 * treated separately */
	snprintf(array_str + offset, C_STR_SIZE - offset, "0x%.2X};", *data++);

	return array_str;
}
#endif
