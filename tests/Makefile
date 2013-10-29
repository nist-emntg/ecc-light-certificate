CC=gcc
CFLAGS=-Wall -DSHA2_USE_INTTYPES_H -DWITH_SHA256
INCLUDEDIR=-I../ecc -I../sha2 -I../certificate
EXT_SOURCES=../ecc/ecc.c ../sha2/sha2.c \
			../certificate/certificate.c \
			../certificate/bit.c
EXT_OBJ=$(EXT_SOURCES:.c=.o)
LDLIBS=
EXECUTABLE= testcertificate

all: $(EXT_SOURCES) $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) -c $< -o $@

$(EXECUTABLE): $(EXT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDEDIR) $(EXT_OBJ) $@.c -o $@

clean:
	rm -f $(EXT_OBJ) $(EXECUTABLE)


