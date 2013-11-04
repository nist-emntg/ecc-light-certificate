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

/* read raw certificate and print the C array of the corresponding
 * serialized certificate */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "certificate.h"
#include "ecc.h"

void print_usage(const char * prgname)
{
	printf("%s [-p] certificate varname\n"
	       "Sign a certificate with a signing party certificate\n"
	       "Mandatory arguments:\n"
	       " certificate: certificate to be printed\n"
	       " signing-party: file containing the certificate of the signing party (that will sign this certificate)\n"
		   "Optional argument:\n"
		   " -p: print the public certificate (omit the secret); note that this argument must be the first argument\n",
	       prgname);
}

int main(int argc, char * const argv[])
{
	int cert_fd;
	s_certificate cert;
	int public = 0, opt, nreads;
	const char * certificate = NULL;
	const char * varname = NULL;
	uint8_t ser_cert[CERT_SIZE];
	char * cert_array = NULL;

	if (argc != 3 && argc != 4) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ecc_init();

	while ((opt = getopt(argc, argv, "p")) != -1) {
		switch (opt) {
			case 'p':
				public = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		printf("here\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	certificate = argv[optind++];
	varname = argv[optind++];

	cert_fd = open(certificate, O_RDONLY);
	if (cert_fd == -1) {
		fprintf(stderr, "unable to open %s\n", certificate);
		perror("open");
		exit(EXIT_FAILURE);
	}

	nreads = read(cert_fd, &cert, sizeof(cert));
	if (nreads != sizeof(cert)) {
		fprintf(stderr, "%s does not contain a valid certificate\n", certificate);
		exit(EXIT_FAILURE);
	}

	if (public) {
		serialize_pub_cert(&cert.pub_cert, ser_cert);
		cert_array = data_to_c_array(ser_cert, PUB_CERT_SIZE, varname);
	} else {
		serialize_cert(&cert, ser_cert);
		cert_array = data_to_c_array(ser_cert, CERT_SIZE, varname);

	}

	if (cert_array) {
		printf("%s\n", cert_array);
	} else {
		fprintf(stderr, "array conversion failed\n");
		exit(EXIT_FAILURE);
	}

	free(cert_array);

	return 0;
}
