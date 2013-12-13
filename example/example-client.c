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

/* a small client program that illustrate what the library can do */

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
uint8_t raw_cacert [112] = {0x00, 0x00, 0x00, 0x00, 0xAC, 0x5B, 0x90, 0xCF, 0x7E, 0x9D, 0xB8, 0x1C, 0x50, 0x75, 0xB4, 0x18, 0x57, 0xBE, 0x1A, 0x19, 0x00, 0x00, 0x00, 0x00, 0xE2, 0xD6, 0xA1, 0x21, 0xF3, 0xEE, 0x32, 0xF6, 0xA6, 0x8B, 0x3D, 0x0B, 0x48, 0x1C, 0xB7, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t raw_cert [132] = {0x00, 0x00, 0x00, 0x00, 0xAC, 0x5B, 0x90, 0xCF, 0x7E, 0x9D, 0xB8, 0x1C, 0x50, 0x75, 0xB4, 0x18, 0x57, 0xBE, 0x1A, 0x19, 0x00, 0x00, 0x00, 0x00, 0xE2, 0xD6, 0xA1, 0x21, 0xF3, 0xEE, 0x32, 0xF6, 0xA6, 0x8B, 0x3D, 0x0B, 0x48, 0x1C, 0xB7, 0x66, 0x2F, 0xD7, 0xFE, 0x53, 0xFC, 0x7D, 0xE2, 0xD3, 0x8F, 0x60, 0x75, 0xB1, 0xC2, 0xEF, 0x14, 0xD5, 0x28, 0x89, 0x6A, 0xEE, 0xC1, 0xB6, 0x0A, 0xDC, 0xC9, 0xEE, 0x79, 0xB2, 0x58, 0x6B, 0xF7, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x48, 0x02, 0xCE, 0x7A, 0xE9, 0x6E, 0x37, 0x7C, 0x1A, 0x2E, 0xA2, 0xAE, 0xFD, 0xF6, 0x12, 0xE7, 0x00, 0x00, 0x00, 0x00, 0xE2, 0xFD, 0xDC, 0xBB, 0x4C, 0x67, 0x3B, 0xE7, 0x64, 0x8F, 0x3E, 0x44, 0x4B, 0xC1, 0x2E, 0xE6, 0x00, 0x00, 0x00, 0x00, 0x10, 0x24, 0x89, 0x57, 0x56, 0xB5, 0x3D, 0xDF, 0x4F, 0xF8, 0x2A, 0xF0, 0x1C, 0x8E, 0x20, 0xC7};


s_certificate * mycert = NULL;
s_pub_certificate * cacert = NULL;

void init_certificate(void)
{
	s_certificate tmp;
	s_pub_certificate tmp2;

	deserialize_cert(raw_cert, &tmp);
	memcpy(raw_cert, &tmp, sizeof(s_certificate));
	mycert = (s_certificate *) raw_cert;

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

	/* receive d'.G */
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
