all: udp-client udp-server
extra: example tools tests
CONTIKI=contiki

WITH_UIP6=1
UIP_CONF_IPV6=1

CFLAGS+= -DUIP_CONF_IPV6_RPL \
		 -DSHA2_USE_INTTYPES_H \
		 -DWITH_SHA256

PROJECT_SOURCEFILES += ecc.c sha2.c certificate.c bit.c
PROJECTDIRS += sha2 ecc certificate

# mc1322x is little endian only
ifeq ($(TARGET),econotag)
CFLAGS+= -DWORDS_LITTLEENDIAN
endif

ifdef WITH_COMPOWER
APPS+=powertrace
CFLAGS+= -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

ifdef SERVER_REPLY
CFLAGS+=-DSERVER_REPLY=$(SERVER_REPLY)
endif
ifdef PERIOD
CFLAGS+=-DPERIOD=$(PERIOD)
endif

include $(CONTIKI)/Makefile.include

example:
	make -C example

tools:
	make -C tools

tests:
	make -C tests
