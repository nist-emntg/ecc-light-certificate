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

/* sign a raw ECC certificate with an other ECC certificate */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "certificate.h"
#include "ecc.h"

void print_usage(const char * prgname)
{
	printf("%s certificate signing-party\n"
	       "Sign a certificate with a signing party certificate\n"
	       "Mandatory arguments:\n"
	       " outcert: file where the certificate to be signed is located\n"
	       " signing-party: file containing the certificate of the signing party (that will sign this certificate)\n",
	       prgname);
}

int main(int argc, const char *argv[])
{
	int cert_fd, signer_fd;
	int nreads, nwrites;
	s_certificate cert, signer;

	if (argc != 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ecc_init();

	memset(&cert, 0, sizeof(cert));
	memset(&signer, 0, sizeof(signer));

	/* for critically secure code, you would need a better seed */
	srand(time(NULL));

	/* open the new file */
	cert_fd = open(argv[1], O_RDWR);
	if (cert_fd == -1) {
		fprintf(stderr, "unable to open %s\n", argv[1]);
		perror("open");
		exit(EXIT_FAILURE);
	}

	signer_fd = open(argv[2], O_RDONLY);
	if (signer_fd == -1) {
		fprintf(stderr, "unable to open %s\n", argv[2]);
		perror("open");
		goto cleanup;
	}

	/* open the certificate to be signed */
	nreads = read(cert_fd, &cert, sizeof(cert));
	if (nreads != sizeof(cert)) {
		fprintf(stderr, "'%s' does not contain a valid certificate\n", argv[2]);
		perror("read");
		goto cleanup;
	}

	/* open the signing party certificate */
	nreads = read(signer_fd, &signer, sizeof(signer));
	if (nreads != sizeof(signer)) {
		fprintf(stderr, "'%s' does not contain a valid certificate\n", argv[2]);
		perror("read");
		goto cleanup;
	}
	close(signer_fd);

	/* sign the certificate */
	sign_certificate(&signer, &cert);

	if (verify_certificate(&signer.pub_cert, &cert.pub_cert)) {
		fprintf(stderr, "unable to verify generated signature\n");
		goto cleanup;
	}

	/* store the certificate */
	if (lseek(cert_fd, SEEK_SET, 0)) {
		perror("lseek");
		goto cleanup;
	}
	nwrites = write(cert_fd, &cert, sizeof(cert));
	if (nwrites != sizeof(cert)) {
		fprintf(stderr, "unable to write the certificate\n");
		perror("write");
		goto cleanup;
	}
	close(cert_fd);

	return 0;

cleanup:
	close(cert_fd);
	exit(EXIT_FAILURE);
}
