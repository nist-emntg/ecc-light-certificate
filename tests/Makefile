DOMIAN_PARAMS=SECP160R1
CURVE_DIR=../ecc/curve-params

CC=gcc
CFLAGS=-g -Wall -DSHA2_USE_INTTYPES_H -DWITH_SHA256 \
	   -DHAVE_ASSERT_H \
	   -DSECP160R1 \
	   -DTHIRTYTWO_BIT_PROCESSOR \
	   -DDOMIAN_PARAMS=$(DOMIAN_PARAMS)
	   #-DSHAMIR_TRICK \

INCLUDEDIR=-I../ecc -I../sha2 -I../certificate
EXT_SOURCES=../ecc/ecc.c ../ecc/nn.c ../ecc/ecdsa.c \
			../sha2/sha2.c \
			../certificate/certificate.c \
			../certificate/bit.c

include ../ecc/curve-params/Makefile.curve_params

EXT_OBJ=$(EXT_SOURCES:.c=.o)
LDLIBS=
EXECUTABLE= testecc testcertificate

all: $(EXT_SOURCES) $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) -c $< -o $@

$(EXECUTABLE): $(EXT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDEDIR) $(EXT_OBJ) $@.c -o $@

clean:
	rm -f $(EXT_OBJ) $(EXECUTABLE)


