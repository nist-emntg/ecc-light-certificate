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

/* Tony Cheneau <tony.cheneau@nist.gov> */

/* a small client program that illustrate what the library can do
 * (this is a variant of the client program, with an invalid certificate) */

#include "certificate.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/in.h>
#include <string.h>

/* contains the serialized certificate for now, but will contains the complete C structure open initialization */
uint8_t raw_cacert [144] = {0x00, 0x00, 0x00, 0x00, 0xA6, 0xAF, 0xBA, 0x45, 0x4A, 0xF2, 0x3B, 0xC7, 0xD2, 0xDD, 0xCD, 0x1B, 0x93, 0x4E, 0x1F, 0x1C, 0xA0, 0xA7, 0x0F, 0xB1, 0xCB, 0xB5, 0x53, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x33, 0xEB, 0xD6, 0x57, 0x27, 0xF3, 0xDA, 0x8A, 0xC2, 0xFA, 0x6B, 0xDB, 0x1C, 0x63, 0x51, 0x8B, 0x68, 0x7C, 0x71, 0xEC, 0x4C, 0x3D, 0x0D, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t raw_bad_cert [172] = {0x00, 0x00, 0x00, 0x00, 0xB8, 0x03, 0x7E, 0xE0, 0xCB, 0xF1, 0x78, 0xD0, 0xD0, 0x12, 0x49, 0xD7, 0xF6, 0x97, 0x1C, 0x9E, 0x37, 0x60, 0x3B, 0x8E, 0x15, 0x07, 0x8A, 0x32, 0x00, 0x00, 0x00, 0x00, 0x42, 0x27, 0xCA, 0x96, 0x73, 0x9F, 0x56, 0x91, 0x23, 0xF9, 0x35, 0xDD, 0x0F, 0xAF, 0x12, 0x1F, 0x37, 0xAA, 0x65, 0x21, 0xE2, 0x99, 0xB6, 0x37, 0x20, 0x69, 0x92, 0xA7, 0xB8, 0x6E, 0x30, 0x79, 0x32, 0xBE, 0x9B, 0x31, 0xB5, 0xD4, 0x94, 0x48, 0x68, 0x1D, 0xFE, 0x8D, 0xA2, 0x71, 0x19, 0xD8, 0x98, 0x5D, 0x6F, 0xF3, 0xE8, 0xD1, 0xFE, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFC, 0x6C, 0x95, 0x35, 0x02, 0xD3, 0xD3, 0xE4, 0x02, 0xA2, 0xFD, 0x4D, 0x95, 0xFD, 0xB0, 0x95, 0x2B, 0xA2, 0x4E, 0x57, 0x94, 0x0C, 0xF7, 0x00, 0x00, 0x00, 0x00, 0x99, 0x3A, 0xAA, 0xA1, 0xF7, 0x64, 0xDE, 0x8B, 0xC7, 0x96, 0x71, 0xB7, 0xE9, 0x80, 0x51, 0x6B, 0xC4, 0x06, 0x89, 0xB7, 0x00, 0xC8, 0x1A, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x1E, 0x22, 0x1D, 0x0F, 0xA9};

s_certificate * mycert = NULL;
s_pub_certificate * cacert = NULL;

void init_certificate(void)
{
	s_certificate tmp;
	s_pub_certificate tmp2;

	deserialize_cert(raw_bad_cert, &tmp);
	memcpy(raw_bad_cert, &tmp, sizeof(s_certificate));
	mycert = (s_certificate *) raw_bad_cert;

	deserialize_pub_cert(raw_cacert, &tmp2);
	memcpy(raw_cacert, &tmp2, sizeof(s_pub_certificate));
	cacert = (s_pub_certificate *) raw_cacert;
}

int main(int argc, const char *argv[])
{
	int sockfd, c;
	struct sockaddr_in addr;
	uint8_t ser_pub_cert[PUB_CERT_SIZE];
	uint8_t ser_cert_server[PUB_CERT_SIZE];
	s_pub_certificate server_cert;
	NN_DIGIT secret[NUMWORDS];
	uint8_t point[2*NUMBYTES], shared_secret[2*NUMBYTES];
	uint8_t key[SHA256_DIGEST_LENGTH];
	uint8_t signature[SIG_LEN];
	unsigned int offset = 0;

	ecc_init();

	/* deserialize the certificate that is stored in the code */
	init_certificate();

	/* simplistic TCP client, uses hardcoded values */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		goto flush_and_exit;
	}


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	addr.sin_port = htons(9999);

	if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("connect");
		goto flush_and_exit;
	}

	serialize_pub_cert(&mycert->pub_cert, ser_pub_cert);

	/* handshake */
	if (send(sockfd, ser_pub_cert, PUB_CERT_SIZE, 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	/* send d.G
	 * (d is variable secret here) */
	ecc_ecdh_from_host(secret, point);

	if (send(sockfd, point, sizeof(point), 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	certificate_ecdsa_sign(mycert, point, sizeof(point), signature);

	if (send(sockfd, signature, sizeof(signature), 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	/* verify that the server certificate is valid */
	if (recv(sockfd, ser_cert_server, sizeof(ser_cert_server), 0) == -1) {
		perror("recv");
		exit(EXIT_FAILURE);
	}
	deserialize_pub_cert(ser_cert_server, &server_cert);

	/* verify that the client certificate is valid */
	if (verify_certificate(cacert, &server_cert)) {
		fprintf(stderr, "server certificate is not trusted\n");
		goto flush_and_exit;
	} else {
		printf("(server certificate is valid)\n");
	}

	/* receive g^j */
	if (recv(sockfd, point, sizeof(point), 0) == -1) {
		perror("recv");
		exit(EXIT_FAILURE);
	}

	/* verify that the signature on d'.G matches the server's certificate */
	if (recv(sockfd, signature, sizeof(signature), 0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}

	if (certificate_ecdsa_verify(&server_cert,
	                             point,
	                             sizeof(point),
	                             signature)) {
		fprintf(stderr, "signature does not match");
		goto flush_and_exit;
	} else {
		printf("(signature d'.G is valid)\n");
	}

	/* compute d.d'.G (this is the shared secret) */
	ecc_ecdh_from_network(secret, point, shared_secret);

	/* derive a longer key */
	ecc_ecdh_derive_key(shared_secret, key);

	/* "encrypted data" (using XOR encoding for more security) */
	while ((c = getchar()) != EOF) {
		uint8_t chr = (uint8_t) c ^ key[offset++ % SHA256_DIGEST_LENGTH];
		if (send(sockfd, &chr, 1, 0) == -1) {
			perror("send");
			exit(EXIT_FAILURE);
		}
	}

	return 0;

flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
