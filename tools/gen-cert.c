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

/* generate a (random) raw ECC certificate */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include "certificate.h"

void print_usage(const char * prgname)
{
	printf("%s outcert [issuer]\n"
	       "Generate a random ECC certificate\n"
	       "Mandatory arguments:\n"
	       " outcert: file where the generated certificate is stored\n"
	       "Optional arguments:\n"
	       " issuer: file containing the certificate of the issuer (that will sign this certificate)\n",
		   prgname);
}

int main(int argc, const char *argv[])
{
	int cert_fd, issuer_fd;
	int nwrites;
	s_certificate cert, issuer;

	if (argc != 2 && argc != 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* for critically secure code, you would need a better seed */
	srand(time(NULL));

	memset(&cert, 0, sizeof(cert));
	memset(&issuer, 0, sizeof(cert));

	/* open the new file */
	cert_fd = open(argv[1], O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
	if (cert_fd == -1) {
		fprintf(stderr, "unable to open %s\n", argv[1]);
		perror("open");
		exit(EXIT_FAILURE);
	}

	/* generate the certificate */
	generate_certificate(&cert);

	if (argc == 3) {
		int nreads = 0;
		/* open the issuer certificate */
		issuer_fd = open(argv[2], O_RDONLY);

		if (issuer_fd == -1) {
			fprintf(stderr, "unable to open %s\n", argv[2]);
			perror("open");
			goto cleanup;
		}

		nreads = read(issuer_fd, &issuer, sizeof(issuer));
		if (nreads != sizeof(issuer)) {
			fprintf(stderr, "'%s' does not contain a valid certificate\n", argv[2]);
			perror("read");
			goto cleanup;
		}

		/* sign the new certificate */
		sign_certificate(&issuer, &cert);

		if (verify_certificate(&issuer.pub_cert, &cert.pub_cert)) {
			fprintf(stderr, "unable to verify generated signature\n");
			goto cleanup;
		}

		close(issuer_fd);
	}


	/* store the certificate */
	nwrites = write(cert_fd, &cert, sizeof(cert));
	if (nwrites != sizeof(cert)) {
		fprintf(stderr, "unable to write the certificate\n");
		perror("write");
		goto cleanup;
	}
	close(cert_fd);

	return 0;
cleanup:
	unlink(argv[2]);
	close(cert_fd);
	exit(EXIT_FAILURE);
}
