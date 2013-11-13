/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/uip-udp-packet.h"
#include "sys/ctimer.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include <stdio.h>
#include <string.h>

#include "certificate.h"

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN		30

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
s_certificate * cert;
s_pub_certificate * cacert;

uint8_t raw_cert [172] = {0x00, 0x00, 0x00, 0x00, 0x1E, 0x09, 0xF4, 0xF2, 0xB5, 0xBA, 0xED, 0xF9, 0xAD, 0xAE, 0x6B, 0x7F, 0x56, 0xA9, 0xA4, 0xAA, 0x05, 0x82, 0xF8, 0x88, 0xD5, 0x39, 0x04, 0x2B, 0x00, 0x00, 0x00, 0x00, 0xC5, 0x63, 0xCB, 0x49, 0x7E, 0x0F, 0x88, 0x5E, 0x08, 0x56, 0xF0, 0x9B, 0x93, 0xFF, 0x47, 0x9F, 0x47, 0x7B, 0xA9, 0x43, 0x6A, 0x97, 0x67, 0xB7, 0x3D, 0x9F, 0x63, 0xC6, 0x3B, 0x96, 0x8C, 0xD2, 0x20, 0xED, 0xD3, 0xDE, 0xEE, 0xCF, 0x05, 0xDA, 0xCB, 0xA2, 0xB0, 0xAD, 0x93, 0x87, 0x33, 0x65, 0x49, 0x84, 0x53, 0xD8, 0xC0, 0x7B, 0xB8, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x88, 0xCE, 0xB6, 0x17, 0x98, 0x6A, 0x16, 0x61, 0x9D, 0x2A, 0xF0, 0x2A, 0xAB, 0x45, 0x7D, 0xBB, 0xD8, 0x7F, 0x48, 0xC9, 0x5C, 0xB6, 0x3A, 0x92, 0x00, 0x00, 0x00, 0x00, 0x65, 0x28, 0xC8, 0x7D, 0x2A, 0xA8, 0x71, 0xA9, 0x04, 0x24, 0x5F, 0x70, 0x86, 0xB0, 0x89, 0x15, 0x48, 0x85, 0x05, 0xB1, 0x14, 0x66, 0xF3, 0x84, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x24, 0x7C, 0x23, 0x20, 0xCC, 0x0C, 0x9A, 0x1A, 0x06, 0x32, 0x96, 0x3E, 0x51, 0x24, 0x15, 0x32, 0xAA, 0x9B, 0x8A, 0x78, 0x3E, 0x9E, 0x69};
uint8_t raw_cacert [144] = {0x00, 0x00, 0x00, 0x00, 0x03, 0xE9, 0xC6, 0x51, 0xF1, 0x7A, 0xB1, 0xDA, 0x58, 0x48, 0x0B, 0x80, 0xBF, 0x84, 0x8C, 0x83, 0x44, 0x28, 0xF4, 0x39, 0x7A, 0xE2, 0xFB, 0x80, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x60, 0x71, 0x9C, 0xDF, 0x2E, 0xEB, 0x4E, 0xA4, 0x15, 0x9C, 0x71, 0xF6, 0xAD, 0xCA, 0x0D, 0x38, 0xC4, 0xF8, 0x88, 0x6C, 0x12, 0xC1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("DATA recv '%s'\n", str);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
  static int seq_id;
  char buf[MAX_PAYLOAD_LEN];

  seq_id++;
  PRINTF("DATA send to %d 'Hello %d'\n",
         server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], seq_id);
  sprintf(buf, "Hello %d from the client", seq_id);
  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
init_crypto(void) {
	s_certificate tmp;
	s_pub_certificate tmp2;

	PRINTF("initializing crypto\n");
	ecc_init();

	deserialize_cert(raw_cert, &tmp);
	memcpy(raw_cert, &tmp, sizeof(s_certificate));
	cert = (s_certificate *) raw_cert;

	deserialize_pub_cert(raw_cacert, &tmp2);
	memcpy(raw_cacert, &tmp2, sizeof(s_pub_certificate));
	cacert = (s_pub_certificate *) raw_cacert;
}
/*---------------------------------------------------------------------------*/
#if 1
static void
test_crypto(void)
{
	int res;
	s_certificate test;
	s_pub_certificate pub_test;
	uint8_t data[200] = {0};
	uint8_t signature[SIG_LEN];

	/* ECDH related */
	NN_DIGIT secret[NUMWORDS];
	uint8_t point[2 * NUMBYTES], shared_secret[2 * NUMBYTES];
	uint8_t key[SHA256_DIGEST_LENGTH];

	/* the following array contains a certificate signed with the same "cacert"
	 * as the "cert" certificate
	 * (we deserialize it here) */
	uint8_t raw_client2 [144] = {0x00, 0x00, 0x00, 0x00, 0xAA, 0xA1, 0x3E, 0x6C, 0x4E, 0xEA, 0xC2, 0xFE, 0x88, 0x1B, 0x72, 0x52, 0xB8, 0xAE, 0x77, 0xF0, 0x8C, 0x6E, 0xFC, 0x22, 0xAE, 0x7D, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x88, 0x3B, 0x0B, 0x63, 0xFA, 0xBD, 0xA5, 0xC6, 0xEF, 0x70, 0x82, 0xB5, 0x74, 0x40, 0x27, 0x84, 0xD6, 0x10, 0x8F, 0x05, 0x67, 0x99, 0x5A, 0x46, 0x3D, 0x9F, 0x63, 0xC6, 0x3B, 0x96, 0x8C, 0xD2, 0x20, 0xED, 0xD3, 0xDE, 0xEE, 0xCF, 0x05, 0xDA, 0xCB, 0xA2, 0xB0, 0xAD, 0x93, 0x87, 0x33, 0x65, 0x49, 0x84, 0x53, 0xD8, 0xC0, 0x7B, 0xB8, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x91, 0x81, 0xF3, 0xF7, 0xD2, 0xE6, 0xE0, 0xE9, 0xA5, 0xB3, 0xEB, 0x81, 0x21, 0x84, 0x0D, 0xEA, 0xFB, 0xFC, 0xBC, 0x3E, 0x8A, 0x7C, 0x69, 0x80, 0x00, 0x00, 0x00, 0x00, 0x65, 0x7E, 0x71, 0x08, 0x2B, 0x4A, 0x39, 0x31, 0x38, 0xF9, 0x0A, 0x84, 0xB5, 0xF2, 0x1A, 0xCA, 0xDA, 0x74, 0x28, 0x78, 0x42, 0x6A, 0x26, 0xC2};

	s_pub_certificate * client2;
	deserialize_pub_cert(raw_client2, (s_pub_certificate *) data);
	memcpy(raw_client2, data, sizeof(s_pub_certificate));
	client2 = (s_pub_certificate * ) raw_client2;

	while (1) {
		/*
		 * certificate operations
		 */
		PRINTF("generate a random certificate\n");
		generate_certificate(&test);
		PRINTF("done - generate a random certificate\n");

		PRINTF("verify own's certificate\n");
		/* verify that the client certificate is valid */
		res = verify_certificate(cacert, &cert->pub_cert);
		if (res) {
			PRINTF("own's certificate is not trusted (%d)\n", res);
		} else {
			PRINTF("own's certificate is valid\n");
		}
		PRINTF("done - verify own's certificate\n");

		PRINTF("verify a client certificate\n");
		/* verify that the client certificate is valid */
		res = verify_certificate(cacert, client2);
		if (res) {
			PRINTF("client certificate is not trusted (%d)\n", res);
		} else {
			PRINTF("client certificate is valid\n");
		}
		PRINTF("done - verify a client certificate\n");

		/**
		 * ECDSA operations
		 */
		PRINTF("sign random data\n");
		certificate_ecdsa_sign(&test,
							   data,
							   sizeof(data),
							   signature);
		PRINTF("done - sign random data\n");


		PRINTF("verifying ECDSA signature (good)\n");
		if (certificate_ecdsa_verify(&test.pub_cert,
								data,
								sizeof(data),
								signature) < 0) {
			PRINTF("unable to verify ECDSA signature\n");
		} else {
			PRINTF("signature is valid\n");
		}
		PRINTF("done - verifying ECDSA signature (good)\n");

		data[0] ^= 0xff; /* break the integrity of the data */

		PRINTF("verifying ECDSA signature (bad 1/2)\n");
		if (certificate_ecdsa_verify(&test.pub_cert,
								data,
								sizeof(data),
								signature) < 0) {
			PRINTF("unable to verify ECDSA signature\n");
		} else {
			PRINTF("signature is valid\n");
		}
		PRINTF("done - verifying ECDSA signature (bad 1/2)\n");

		data[0] ^= 0xff; /* reverse the previous operation */
		signature[0] ^= 0xff; /* break the integrity of the signature */

		PRINTF("verifying ECDSA signature (bad 2/2)\n");
		if (certificate_ecdsa_verify(&test.pub_cert,
								data,
								sizeof(data),
								signature) < 0) {
			PRINTF("unable to verify ECDSA signature\n");
		} else {
			PRINTF("signature is valid\n");
		}
		PRINTF("done - verifying ECDSA signature (bad 2/2)\n");

		/**
		 * serialization operations
		 */

		PRINTF("serialization\n");
		serialize_pub_cert(&test.pub_cert, data);
		PRINTF("done - serialization\n");

		PRINTF("deserialization\n");
		deserialize_pub_cert(data, &pub_test);
		PRINTF("done - deserialization\n");
		if (memcmp(&test.pub_cert, &pub_test, sizeof(s_pub_certificate))) {
			PRINTF("serialization failed\n");
		} else {
			PRINTF("serialization succeeded\n");
		}


		/**
		 * ECDH operations
		 */

		PRINTF("ECDH first message\n");
		/* send g^k
		 * (k is variable secret here) */
		ecc_ecdh_from_host(secret, point);
		PRINTF("done - ECDH first message\n");

		PRINTF("ECDH second message\n");
		/* compute g^(k+j) (this is the shared secret) */
		ecc_ecdh_from_network(secret, point, shared_secret);
		PRINTF("done - ECDH second message\n");

		PRINTF("ECDH derive key\n");
		/* derive a longer key */
		ecc_ecdh_derive_key(shared_secret, key);
		PRINTF("done - ECDH derive key\n");
	}
}
#endif
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

/* The choice of server address determines its 6LoPAN header compression.
 * (Our address will be compressed Mode 3 since it is derived from our link-local address)
 * Obviously the choice made here must also be selected in udp-server.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 *
 * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */

#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer;
#if WITH_COMPOWER
  static int print = 0;
#endif

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  init_crypto();

  test_crypto();

  set_global_address();

  PRINTF("UDP client process started\n");

  print_local_addresses();

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);
  if(client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT));

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif

  etimer_set(&periodic, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }

    if(etimer_expired(&periodic)) {
      etimer_reset(&periodic);
      ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

#if WITH_COMPOWER
      if (print == 0) {
	powertrace_print("#P");
      }
      if (++print == 3) {
	print = 0;
      }
#endif

    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
