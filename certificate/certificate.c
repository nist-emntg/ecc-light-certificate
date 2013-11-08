#include "certificate.h"
#include "bit.h"
#include "prng.h"
#include "ecdsa.h"

#include <string.h>

#ifndef WITH_CONTIKI
#include <stdio.h>
#endif

#define C_STR_SIZE 4096

int generate_certificate(s_certificate *out_cert)
{
	memset(out_cert, 0, sizeof(* out_cert));

	ecc_gen_private_key(out_cert->secret);
	ecc_gen_pub_key(out_cert->secret, &out_cert->pub_cert.pub);

	return 0;
}


/* return 0 if the certificate is valid, -1 or -2 otherwise */
int verify_certificate(s_pub_certificate * signer_cert,
                       s_pub_certificate * certificate)
{
	SHA256_CTX c256;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	/* fix the endianness */
	uint8_t pub_x[NUMBYTES], pub_y[NUMBYTES];
	NN_Encode(pub_x, NUMBYTES, signer_cert->pub.x, NUMWORDS);
	NN_Encode(pub_y, NUMBYTES, signer_cert->pub.y, NUMWORDS);

	memset(hash, 0, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, NUMBYTES);
	SHA256_Update(&c256, pub_y, NUMBYTES);
	SHA256_Update(&c256, (uint8_t *)signer_cert->issuer,
	              sizeof(signer_cert->issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	if (memcmp(hash, certificate->issuer, SHA256_DIGEST_LENGTH)) {
		return -1; /* trusted certificate does not match the issuer certificate */
	}

	NN_Encode(pub_x, NUMBYTES, certificate->pub.x, NUMWORDS);
	NN_Encode(pub_y, NUMBYTES, certificate->pub.y, NUMWORDS);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, NUMBYTES);
	SHA256_Update(&c256, pub_y, NUMBYTES);
	SHA256_Update(&c256, (unsigned char*)certificate->issuer,
	              sizeof(certificate->issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	ecdsa_init(&signer_cert->pub);

	if (ecdsa_verify(hash,
	                 certificate->signature_r,
	                 certificate->signature_s,
	                 &signer_cert->pub) != 1) {
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
	int offset = 0;
	NN_Decode(src->pub.x, NUMWORDS, dst, NUMBYTES);
	offset += NUMBYTES;
	NN_Decode(src->pub.y, NUMWORDS, dst, NUMBYTES);
	offset += 2 * NUMBYTES;
	memcpy(dst + offset, src->issuer, SHA256_DIGEST_LENGTH);
	offset += SHA256_DIGEST_LENGTH;
	NN_Decode(src->signature_r, NUMWORDS, dst + offset, NUMBYTES);
	offset += NUMBYTES;
	NN_Decode(src->signature_s, NUMWORDS, dst + offset, NUMBYTES);

	return 0;
}

int serialize_cert(s_certificate * src, uint8_t dst[CERT_SIZE])
{
	int offset = 0;
	NN_Decode(src->pub_cert.pub.x, NUMWORDS, dst, NUMBYTES);
	offset += NUMBYTES;
	NN_Decode(src->pub_cert.pub.y, NUMWORDS, dst, NUMBYTES);
	offset += 2 * NUMBYTES;
	memcpy(dst + offset, src->pub_cert.issuer, SHA256_DIGEST_LENGTH);
	offset += SHA256_DIGEST_LENGTH;
	NN_Decode(src->pub_cert.signature_r, NUMWORDS, dst + offset, NUMBYTES);
	offset += NUMBYTES;
	NN_Decode(src->pub_cert.signature_s, NUMWORDS, dst + offset, NUMBYTES);
	offset += NUMBYTES;
	NN_Decode(src->secret, NUMWORDS, dst + offset, NUMBYTES);

	return 0;
}

int deserialize_pub_cert(uint8_t * src, s_pub_certificate * dst)
{
	int offset = 0;
	NN_Encode(src, NUMBYTES, dst->pub.x, NUMWORDS);
	offset += NUMBYTES;
	NN_Encode(src + offset, NUMBYTES, dst->pub.y, NUMWORDS);
	offset += NUMBYTES;
	memcpy(dst->issuer, src + offset, SHA256_DIGEST_LENGTH);
	offset += SHA256_DIGEST_LENGTH;
	NN_Encode(src + offset, NUMBYTES, dst->signature_r, NUMWORDS);
	offset += NUMBYTES;
	NN_Encode(src + offset, NUMBYTES, dst->signature_s, NUMWORDS);
	return 0;
}

int deserialize_cert(uint8_t * src, s_certificate * dst)
{
	int offset = 0;
	NN_Encode(src, NUMBYTES, dst->pub_cert.pub.x, NUMWORDS);
	offset += NUMBYTES;
	NN_Encode(src + offset, NUMBYTES, dst->pub_cert.pub.y, NUMWORDS);
	offset += NUMBYTES;
	memcpy(dst->pub_cert.issuer, src + offset, SHA256_DIGEST_LENGTH);
	offset += SHA256_DIGEST_LENGTH;
	NN_Encode(src + offset, NUMBYTES, dst->pub_cert.signature_r, NUMWORDS);
	offset += NUMBYTES;
	NN_Encode(src + offset, NUMBYTES, dst->pub_cert.signature_s, NUMWORDS);
	offset += NUMBYTES;
	NN_Encode(src + offset, NUMBYTES, dst->secret, NUMWORDS);

	return 0;
}

int certificate_ecdsa_sign(s_certificate * certificate,
                           const uint8_t * data,
                           int length,
                           uint8_t * signature)
{
	SHA256_CTX c256;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	NN_DIGIT signature_r[NUMWORDS];
	NN_DIGIT signature_s[NUMWORDS];

	SHA256_Init(&c256);
	SHA256_Update(&c256, data, length);
	SHA256_Final(hash, &c256);

	memset(signature_r, 0, NUMBYTES);
	memset(signature_s, 0, NUMBYTES);


	ecdsa_init(&certificate->pub_cert.pub);
	/* sign the hash */
	ecdsa_sign(hash, signature_r, signature_s, certificate->secret);

	/* convert the fields to the proper endianness */
	NN_Decode(signature_r, NUMWORDS, signature, NUMBYTES);
	NN_Decode(signature_s, NUMWORDS, signature + NUMBYTES, NUMBYTES);

	return 0;
}

int certificate_ecdsa_verify(s_pub_certificate * certificate,
                             const uint8_t * data,
                             int length,
                             uint8_t * signature)
{
	SHA256_CTX c256;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	NN_DIGIT signature_r[NUMWORDS], signature_s[NUMWORDS];

	NN_Encode(signature, NUMBYTES, signature_r, NUMWORDS);
	NN_Encode(signature + NUMBYTES, NUMBYTES, signature_s, NUMWORDS);

	memset(hash, 0, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c256);
	SHA256_Update(&c256, data, length);
	SHA256_Final((uint8_t *) hash, &c256);

	ecdsa_init(&certificate->pub);
	if (ecdsa_verify(hash, signature_r, signature_s, &certificate->pub) != 1) {
		return -1; /* signature is invalid */
	}

	return 0;
}

int ecc_ecdh_from_host(NN_DIGIT secret[NUMWORDS],
                       uint8_t point[2 * NUMBYTES])
{
	point_t result;
	point_t * G = ecc_get_base_p();

	prng((uint8_t *)secret, NUMBYTES);

	ecc_mul(&result, G, secret);
	NN_Decode(result.x, NUMWORDS, point, NUMBYTES);
	NN_Decode(result.y, NUMWORDS, point + NUMBYTES, NUMBYTES);

	return 0;
}

int ecc_ecdh_from_network(NN_DIGIT secret[NUMWORDS],
                          uint8_t point[2 * NUMBYTES],
                          uint8_t shared_secret[2 * NUMBYTES])
{

	point_t pub, result;

	NN_Encode(point, NUMBYTES, pub.x, NUMWORDS);
	NN_Encode(point + NUMBYTES, NUMBYTES, pub.y, NUMWORDS);

	ecc_mul(&result, &pub, secret);

	NN_Decode(result.x, NUMWORDS, shared_secret, NUMBYTES);
	NN_Decode(result.y, NUMWORDS, shared_secret + NUMBYTES, NUMBYTES);

	return 0;
}

int ecc_ecdh_derive_key(uint8_t shared_secret[2 * NUMBYTES],  uint8_t key[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX c256;

	SHA256_Init(&c256);
	SHA256_Update(&c256, shared_secret, 2*NUMBYTES);
	SHA256_Final(key, &c256);

	return 0;
}

#ifndef WITH_CONTIKI
#include <string.h>
void sign_certificate(s_certificate * signing_party,
                      s_certificate * certificate)
{
	uint8_t pub_x[NUMBYTES], pub_y[NUMBYTES];
	SHA256_CTX c256;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	/* convert the fields to the proper endianness */
	NN_Encode(pub_x, NUMBYTES, signing_party->pub_cert.pub.x, NUMWORDS);
	NN_Encode(pub_y, NUMBYTES, signing_party->pub_cert.pub.y, NUMWORDS);

	memset(hash, 0, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, NUMBYTES);
	SHA256_Update(&c256, pub_y, NUMBYTES);
	SHA256_Update(&c256, (uint8_t *)signing_party->pub_cert.issuer,
	              sizeof(signing_party->pub_cert.issuer));
	SHA256_Final((uint8_t *) certificate->pub_cert.issuer, &c256);

	memset(certificate->pub_cert.signature_r, 0, NUMBYTES);
	memset(certificate->pub_cert.signature_s, 0, NUMBYTES);

	/* convert the fields to the proper endianness */
	NN_Encode(pub_x, NUMBYTES, certificate->pub_cert.pub.x, NUMWORDS);
	NN_Encode(pub_y, NUMBYTES, certificate->pub_cert.pub.y, NUMWORDS);

	/* compute hash first on the certificate whose signature fields are zeroed out */
	SHA256_Init(&c256);
	SHA256_Update(&c256, pub_x, NUMBYTES);
	SHA256_Update(&c256, pub_y, NUMBYTES);
	SHA256_Update(&c256, (uint8_t *)certificate->pub_cert.issuer,
	              sizeof(certificate->pub_cert.issuer));
	SHA256_Final((uint8_t *) hash, &c256);

	ecdsa_init(&signing_party->pub_cert.pub);

	/* sign the hash */
	ecdsa_sign(hash,
	           certificate->pub_cert.signature_r,
	           certificate->pub_cert.signature_s,
	           signing_party->secret
	          );
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
