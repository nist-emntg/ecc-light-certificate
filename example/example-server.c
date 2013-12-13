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
uint8_t raw_cacert [144] = {0x00, 0x00, 0x00, 0x00, 0xA6, 0xAF, 0xBA, 0x45, 0x4A, 0xF2, 0x3B, 0xC7, 0xD2, 0xDD, 0xCD, 0x1B, 0x93, 0x4E, 0x1F, 0x1C, 0xA0, 0xA7, 0x0F, 0xB1, 0xCB, 0xB5, 0x53, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x33, 0xEB, 0xD6, 0x57, 0x27, 0xF3, 0xDA, 0x8A, 0xC2, 0xFA, 0x6B, 0xDB, 0x1C, 0x63, 0x51, 0x8B, 0x68, 0x7C, 0x71, 0xEC, 0x4C, 0x3D, 0x0D, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t raw_cert [172] = {0x00, 0x00, 0x00, 0x00, 0x6E, 0xD7, 0xD4, 0x5E, 0x36, 0xD1, 0x72, 0xBA, 0x59, 0xD0, 0xCB, 0xDA, 0xC2, 0x34, 0xA7, 0xE6, 0x3E, 0xE0, 0x01, 0xE5, 0x81, 0xDF, 0x5F, 0x7D, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x49, 0xF2, 0xA8, 0xE5, 0xDC, 0xA8, 0x28, 0x4E, 0x5E, 0x5E, 0xC9, 0x67, 0x80, 0xB7, 0x97, 0x6E, 0x31, 0x0C, 0x12, 0x34, 0x62, 0x49, 0x8E, 0xF3, 0x5F, 0xD1, 0x02, 0x73, 0x6A, 0x6B, 0x60, 0x1D, 0xFA, 0x73, 0xDC, 0x9F, 0xAA, 0xBD, 0x2B, 0xBC, 0xD1, 0x47, 0x63, 0x0B, 0x4C, 0x89, 0x2E, 0xA1, 0xB4, 0x14, 0x74, 0xFA, 0x13, 0x4F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x7B, 0x25, 0xF8, 0x57, 0x0C, 0x2C, 0xC2, 0x39, 0x93, 0x16, 0x00, 0xD1, 0x10, 0x12, 0xBC, 0x86, 0x5F, 0x87, 0xD3, 0x24, 0xAF, 0x00, 0x15, 0x47, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x4C, 0x7A, 0x5D, 0xF2, 0xC1, 0x68, 0x6E, 0xCE, 0x89, 0x4E, 0x26, 0xB0, 0x6C, 0x75, 0x18, 0x9F, 0x11, 0x9C, 0x72, 0x33, 0xDB, 0x79, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAD, 0xB8, 0xF9, 0xD0, 0xC0, 0x74};

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
	int sockfd, newfd, chr;
	socklen_t cliaddr_len;
	struct sockaddr_in addr, cliaddr;
	uint8_t ser_pub_cert[PUB_CERT_SIZE];
	uint8_t ser_client_cert[PUB_CERT_SIZE];
	s_pub_certificate client_cert;
	NN_DIGIT secret[NUMWORDS];
	uint8_t point[2*NUMBYTES ], shared_secret[2*NUMBYTES]; uint8_t key[SHA256_DIGEST_LENGTH];
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

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
				(int[]) { 1 },
				sizeof(int)) == -1) {
		perror("setsockopt");
		goto flush_and_exit;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	addr.sin_port = htons(9999);

	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("bind");
		goto flush_and_exit;
	}

	if (listen(sockfd, 1)) {
		perror("listen");
		goto flush_and_exit;
	}

	printf("waiting for a connection\n");
	if ((newfd = accept(sockfd, (struct sockaddr *) &cliaddr, &cliaddr_len)) == -1) {
		perror("accept");
		goto flush_and_exit;
	}
	close(sockfd);

	printf("accepting a connection from a client\n");

	serialize_pub_cert(&mycert->pub_cert, ser_pub_cert);

	/* handshake */
	if (send(newfd, ser_pub_cert, PUB_CERT_SIZE, 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	/* send g^k
	 * (k is variable secret here) */
	ecc_ecdh_from_host(secret, point);

	if (send(newfd, point, sizeof(point), 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	certificate_ecdsa_sign(mycert, point, sizeof(point), signature);
	/* signature[0] ^= 0xff; */

	if (send(newfd, signature, sizeof(signature), 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	if (recv(newfd, ser_client_cert, sizeof(ser_client_cert), 0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}
	deserialize_pub_cert(ser_client_cert, &client_cert);

	/* verify that the client certificate is valid */
	if (verify_certificate(cacert, &client_cert)) {
		fprintf(stderr, "client certificate is not trusted\n");
		goto flush_and_exit;
	} else {
		printf("(client certificate is valid)\n");
	}

	/* receive g^j */
	if (recv(newfd, point, sizeof(point), 0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}

	/* verify that the signature on g^j matches the server's certificate */
	if (recv(newfd, signature, sizeof(signature), 0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}

	if (certificate_ecdsa_verify(&client_cert,
				point,
				sizeof(point),
				signature)) {
		fprintf(stderr, "signature does not match");
		goto flush_and_exit;
	} else {
		printf("(signature g^j is valid)\n");
	}

	/* compute g^(k+j) (this is the shared secret) */
	ecc_ecdh_from_network(secret, point, shared_secret);

	/* derive a longer key */
	ecc_ecdh_derive_key(shared_secret, key);

	/* "encrypted data" (using XOR encoding for more security) */
	while (recv(newfd, &chr, 1, 0) > 0) {
		putchar(chr ^ key[offset++ % SHA256_DIGEST_LENGTH]);
		fflush(stdout);
	}

	return 0
		;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
