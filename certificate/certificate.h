/*
* Conditions Of Use
*
* This software was developed by employees of the National Institute of
* Standards and Technology (NIST), and others.
* This software has been contributed to the public domain.
* Pursuant to title 15 United States Code Section 105, works of NIST
* employees are not subject to copyright protection in the United States
* and are considered to be in the public domain.
* As a result, a formal license is not needed to use this software.
*
* This software is provided "AS IS."
* NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
* OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
* AND DATA ACCURACY. NIST does not warrant or make any representations
* regarding the use of the software or the results thereof, including but
* not limited to the correctness, accuracy, reliability or usefulness of
* this software.
*/

/**
 * @file certificate.h
 * @brief A library for managing lightweight (~200 bytes) ECC certificates
 * @author Tony Cheneau <tony.cheneau@nist.gov>
 * @version 0.1
 * @date 2013-10-22
 */

#ifndef __TINYDTLS_CERTIFICATE_H
#define __TINYDTLS_CERTIFICATE_H

#include <sys/types.h>

#include <ecc.h>
#include <ecdsa.h>
#include <sha2.h>

/**
 * @name various size of a certificate material when transported
 * @{ */
#define CERT_SIZE (2* NUMBYTES + SHA256_DIGEST_LENGTH + 2 * NUMBYTES + NUMBYTES)
#define PUB_CERT_SIZE (2* NUMBYTES + SHA256_DIGEST_LENGTH + 2 * NUMBYTES)
#define SIG_LEN 72
/**  @} */


/** A public certificate
 * for in-memory representation
 * note: base point is not necessary here, as it is shared by all other nodes */
typedef struct
{
	/** ECC pubkey */
	point_t pub;
	/** hash of the ECC pubkey of signing party */
	uint8_t issuer[SHA256_DIGEST_LENGTH];
	/** signature of the signing party (ECDSA signature) (1/2) */
	NN_DIGIT signature_r[NUMWORDS];
	/** signature of the signing party (ECDSA signature) (2/2) */
	NN_DIGIT signature_s[NUMWORDS];
	/** @} */
} s_pub_certificate;

/** A private certificate
 * for in-memory representation */
typedef struct
{
	/** public part of the certificate */
	s_pub_certificate pub_cert;
	/** private key */
	NN_DIGIT secret[NUMWORDS];
} s_certificate;

/** @name general
 * General certificate management function
 */
/** @{ */

/**
 * @brief Generate a new certificate
 *
 * This certificate might need to be signed (using sign_certificate())
 *
 * @param out_cert generated certificate
 *
 * @return 1 on success (always succeed)
 */
int generate_certificate(s_certificate * out_cert);

#ifndef WITH_CONTIKI
/**
 * @brief Sign a certificate (certificate) using a signing party's certificate
 *
 * The certificate that is signed is modified (to add the signature of the signing party)
 *
 * @param signing_party certificate of the signing party
 * @param certificate the certificate being signed
 */
void sign_certificate(s_certificate * signing_party, s_certificate * certificate);
#endif

/**
 * @brief Verify a certificate against its signer
 *
 * @param signer_cert the signer certificate
 * @param certificate the certificate to be verified
 *
 * @return 0 if the certificate is valid, a negative value otherwise
 */
int verify_certificate(s_pub_certificate * signer_cert, s_pub_certificate * certificate);


/**
 * @brief Verify a certificate path of length path_length against a certificate authority
 *
 * @param cert_authority public certificate of a trusted certificate authority
 * @param cert_path a pointer to an array of certificate
 * @param path_length number of certificates in cert_path
 *
 * @return 0 if the certificate is valid, a negative value otherwise
 */
int verify_certificate_path(s_pub_certificate * cert_authority,
                            s_pub_certificate cert_path[],
                            uint8_t path_length);
/** @} */

/** @name serialization
 * Serialization functions
 */
/** @{ */

#ifdef WITH_CONTIKI
/**
 * @brief Convert arbitrary data to a C array "string" (for embedding the string in a program)
 *
 * @param data data to be converted
 * @param datalen length of data
 * @param dataname name of the C array "string"
 *
 * @return pointer to the resulting "string"; this pointer needs to be freed
 */
char * data_to_c_array(uint8_t * data, int datalen, char * dataname);
#endif

/**
 * @brief Serialize a public certificate
 *
 * @param src certificate to serialize
 * @param dst[PUB_CERT_SIZE] array containing the serialized certificate
 *
 * @return 0 on success. Always succeed.
 */
int serialize_pub_cert(s_pub_certificate * src, uint8_t dst[PUB_CERT_SIZE]);

/**
 * @brief Serialize a private certificate
 *
 * @param src certificate to serialize
 * @param dst[CERT_SIZE] array containing the serialized certificate (must be allocated)
 *
 * @return 0 on success. Always succeed.
 */
int serialize_cert(s_certificate * src, uint8_t dst[CERT_SIZE]);

/**
 * @brief Deserialize a public certificate
 *
 * @param src serialized certificate to deserialize (must be PUB_CERT_SIZE long)
 * @param dst certificate to be filled with the information from the serialized certificate
 *
 * @return 0 on success. Always succeed.
 */
int deserialize_pub_cert(uint8_t * src, s_pub_certificate * dst);

/**
 * @brief Deserialize a private certificate
 *
 * @param src serialized certificate to deserialize (must be CERT_SIZE long)
 * @param dst certificate to be filled with the information from the serialized certificate
 *
 * @return 0 on success. Always succeed.
 */
int deserialize_cert(uint8_t * src, s_certificate * dst);

/** @} */

/** @name signature
 * Signature primitives
 */
/** @{ */


/**
 * @brief ECDSA signature generation
 *
 * @param certificate certificate used for the signature generation
 * @param data data to be signed
 * @param length length of the data to be signed
 * @param signature signature (contains both R & S), must be able to store 72 bytes (SIG_LEN)
 *
 * @return 0 on success. Always succeed.
 */
int certificate_ecdsa_sign(s_certificate * certificate,
                           const uint8_t * data,
                           int length,
                           uint8_t * signature);

/**
 * @brief ECDSA signature verification
 *
 * @param certificate certificate used for signature verification
 * @param data data to be verified
 * @param length length of the data to be verified
 * @param signature signature to be verified (is 72 bytes long, SIG_LEN)
 *
 * @return 0 on success. Always succeed.
 */
int certificate_ecdsa_verify(s_pub_certificate * certificate,
                             const uint8_t * data,
                             int length,
                             uint8_t * signature);

/** @} */

/** @name ECDH
 * ECDH helper code
 *
 * (use the same notation as the Section 4 of RFC 6090)
 */
/** @{ */

/**
 * @brief Compute the point g^k (where k is the secret)
 *
 * g is the curve generator
 *
 * @param secret[NUMWORDS] store a NUMBYTES bytes random integer (generated by the function and must be passed to ecc_ecdh_from_network() later on)
 * @param point[2 * NUMBYTES] store the new point (g^k)
 *
 * @return 0 on success. Always succeed.
 */
int ecc_ecdh_from_host(NN_DIGIT secret[NUMWORDS],
                       uint8_t point[2*NUMBYTES]);

/**
 * @brief Compute the point g^(k+j)
 *
 * @param secret[NUMWORDS] NUMBYTES bytes secret computed by ecc_ecdh_from_host()
 * @param point[2*NUMBYTES] point that was transmitted by the other party (contains g^j)
 * @param shared_secret[2*NUMBYTES] store the shared secret (g^(k+j))
 *
 * @return 0 on success. Always succeed.
 */
int ecc_ecdh_from_network(NN_DIGIT secret[NUMWORDS],
                          uint8_t point[2*NUMBYTES],
                          uint8_t shared_secret[2*NUMBYTES]);
/**
 * @brief Derive a 32 bytes key from the shared_secret
 *
 * @param shared_secret[2*NUMBYTES] point that contains the shared secret (g^(k+j))
 * @param key[SHA256_DIGEST_LENGTH] store the 32 bytes key
 *
 * @return 0 on success. Always succeed.
 */
int ecc_ecdh_derive_key(uint8_t shared_secret[2*NUMBYTES],  uint8_t key[SHA256_DIGEST_LENGTH]);
/** @} */

#endif /* __TINYDTLS_CERTIFICATE_H */
