include ../Makefile.curve
CURVE_DIR=../ecc/curve-params

CC=gcc
CFLAGS=-g -Wall -DSHA2_USE_INTTYPES_H -DWITH_SHA256 \
	   -DHAVE_ASSERT_H \
	   -D$(DOMAIN_PARAMS) \
	   -DTHIRTYTWO_BIT_PROCESSOR \
	   -DDOMAIN_PARAMS=$(DOMAIN_PARAMS)

INCLUDEDIR=-I../ecc -I../sha2 -I../certificate
EXT_SOURCES=../ecc/ecc.c ../ecc/nn.c ../ecc/ecdsa.c \
			../sha2/sha2.c \
			../certificate/certificate.c

include ../ecc/curve-params/Makefile.curve_params

EXT_OBJ=$(EXT_SOURCES:.c=.o)
EXECUTABLE= convert-cert-to-array gen-cert  sign-cert

all: $(EXT_SOURCES) $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) -c $< -o $@

$(EXECUTABLE): $(EXT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDEDIR) $(EXT_OBJ) $@.c -o $@

clean:
	rm -f $(EXT_OBJ) $(EXECUTABLE)


