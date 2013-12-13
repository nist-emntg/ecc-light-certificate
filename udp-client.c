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

#if DOMAIN_PARAMS != SECP192K1
#error "Domain parameter does not match"
#endif

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define UDP_AUTH_PORT   4242

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME	        (random_rand() % (SEND_INTERVAL))
#define AUTH_TIMEOUT       (10 * CLOCK_SECOND)
#define MAX_PAYLOAD_LEN		30
#define AUTH_MSG_LEN        (PUB_CERT_SIZE + 2*NUMBYTES + SIG_LEN)

static struct uip_udp_conn *client_conn;
static struct uip_udp_conn *auth_conn;
static uip_ipaddr_t server_ipaddr;
static s_certificate * cert;
static s_pub_certificate * cacert;


uint8_t raw_cacert [144] = {0x00, 0x00, 0x00, 0x00, 0x28, 0x17, 0xB0, 0xD5, 0xAF, 0x3A, 0x2E, 0xED, 0x04, 0x05, 0x22, 0x29, 0x83, 0x81, 0x77, 0xCC, 0x47, 0x57, 0xD7, 0x62, 0x37, 0xA0, 0xE9, 0xA3, 0x00, 0x00, 0x00, 0x00, 0xB7, 0x29, 0xF3, 0xD0, 0xE5, 0x77, 0x28, 0x96, 0x31, 0xAF, 0x00, 0xE2, 0x38, 0xFF, 0x09, 0xD8, 0xC8, 0x43, 0xE0, 0xC8, 0x90, 0xEA, 0x4F, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t raw_cert [172] = {0x00, 0x00, 0x00, 0x00, 0xFE, 0xA9, 0x67, 0x1A, 0x6A, 0x62, 0x34, 0x97, 0xCC, 0x72, 0x50, 0x65, 0xD7, 0xE5, 0xFE, 0x84, 0x3E, 0x8F, 0x80, 0x7B, 0xDB, 0x27, 0x94, 0xF1, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x81, 0x15, 0xB7, 0xA2, 0x0C, 0x75, 0x69, 0xB0, 0x83, 0x68, 0x2E, 0x38, 0x6D, 0x89, 0xEB, 0x1E, 0x17, 0xC4, 0xE2, 0x06, 0x85, 0xC0, 0x82, 0x2D, 0x02, 0xDD, 0xCC, 0x19, 0xCC, 0x9B, 0xEF, 0xEE, 0x76, 0x21, 0x5A, 0xEE, 0xFD, 0x11, 0xE1, 0xB5, 0xA4, 0x48, 0x11, 0x15, 0x8E, 0xFD, 0xD4, 0xAA, 0xB6, 0xDC, 0xBB, 0xEF, 0x64, 0xED, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x19, 0xAA, 0xA7, 0xFA, 0xC7, 0xD8, 0x71, 0x58, 0x0C, 0x1E, 0x49, 0x20, 0xF3, 0xF7, 0xCB, 0xC6, 0x3D, 0xAA, 0x49, 0x0C, 0x47, 0xA9, 0xEC, 0xBF, 0x00, 0x00, 0x00, 0x00, 0xAD, 0xA1, 0x41, 0x08, 0xD9, 0x34, 0x28, 0xAD, 0x67, 0x69, 0xE9, 0xFC, 0xD1, 0x6F, 0xE7, 0x0A, 0xF0, 0x83, 0x1C, 0x97, 0xD0, 0xD7, 0x47, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEA, 0x44, 0x66, 0x11, 0xB6};

enum auth_state {
	UNAUTHENTICATED = 0,
	WAITING_FOR_RESPONSE,
	AUTHENTICATED
};

static enum auth_state authentication_state = UNAUTHENTICATED;


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
reset_auth(void *ptr)
{
	PRINTF("Authentication timed out\n");
	authentication_state = UNAUTHENTICATED;
	process_poll(&udp_client_process);
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
#if 0
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

uint8_t raw_client2 [144] = {0x00, 0x00, 0x00, 0x00, 0x63, 0x2A, 0xDC, 0x39, 0xC2, 0x40, 0xC9, 0x64, 0xC6, 0xEE, 0xD4, 0xB6, 0xE3, 0x03, 0x18, 0xD2, 0x95, 0x3D, 0x1D, 0xBF, 0x21, 0x48, 0xD2, 0x49, 0x00, 0x00, 0x00, 0x00, 0xD4, 0xA9, 0x9E, 0x8D, 0xC8, 0x42, 0x9C, 0x0D, 0xE5, 0xC1, 0x56, 0x61, 0x59, 0xD3, 0x39, 0x37, 0x2C, 0x7C, 0xFB, 0x90, 0x28, 0x58, 0x2C, 0x81, 0xCF, 0x31, 0x17, 0x15, 0x2A, 0xD4, 0xC4, 0xCA, 0xE2, 0x11, 0x1A, 0xB8, 0x46, 0x57, 0x19, 0xBA, 0xA9, 0x2E, 0xFC, 0x4D, 0x0F, 0xE0, 0xF6, 0xBF, 0xA7, 0x7E, 0x48, 0xA7, 0xF8, 0x75, 0x5A, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x36, 0x73, 0x00, 0xCC, 0x60, 0x9E, 0xD9, 0xD5, 0x84, 0x7A, 0x58, 0xF0, 0x84, 0x73, 0xEE, 0xAC, 0xFF, 0x36, 0x37, 0x14, 0x23, 0x7A, 0xB5, 0xF2, 0x00, 0x00, 0x00, 0x00, 0x32, 0x3A, 0x36, 0x64, 0xEF, 0x32, 0xEB, 0x5E, 0x82, 0x08, 0xAD, 0xAE, 0x7F, 0x51, 0xAE, 0x8D, 0x7D, 0xE2, 0xE5, 0xCD, 0xD9, 0xD4, 0x4B, 0x8B};

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
		/* send d.G=Q
		 * (k is variable secret here) */
		ecc_ecdh_from_host(secret, point);
		PRINTF("done - ECDH first message\n");

		PRINTF("ECDH second message\n");
		/* compute d'.Q (this is the shared secret) */
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
  static struct ctimer backoff_timer, auth_timer;
  static int ret = 0;
  static NN_DIGIT secret[NUMWORDS];
  static uint8_t point[2*NUMBYTES], shared_secret[2*NUMBYTES];
  static uint8_t key[SHA256_DIGEST_LENGTH];
#if WITH_COMPOWER
  static int print = 0;
#endif

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  init_crypto();

  /* test_crypto(); */

  set_global_address();

  PRINTF("UDP client process started\n");

  /* The client runs with a 100% duty cycle in order to ensure high
	 packet reception rates. */
  NETSTACK_MAC.off(1);

  print_local_addresses();

  /* new connection for running the authentication */
  auth_conn = udp_new(NULL, UIP_HTONS(UDP_AUTH_PORT), NULL);
  if (auth_conn == NULL) {
	PRINTF("No UDP connection available, exiting the process!\n");
	PROCESS_EXIT();
  }
  udp_bind(auth_conn, UIP_HTONS(UDP_AUTH_PORT));

  while(authentication_state != AUTHENTICATED) {
	  if (authentication_state == UNAUTHENTICATED) {
		  uint8_t buf[AUTH_MSG_LEN];
		  int buf_len = 0;
		  int i;

		  /* send in the public certificate */
		  serialize_pub_cert(&cert->pub_cert, buf);
		  buf_len += PUB_CERT_SIZE;

		  PRINTF("Initiating authentication\n");
		  /* compute the local ECDH secret */
		  ecc_ecdh_from_host(secret, point);
		  memcpy(buf + buf_len, point, sizeof(point));
		  buf_len += sizeof(point);

		  /* add the signature */
		  certificate_ecdsa_sign(cert, point, sizeof(point), buf + buf_len);
		  buf_len += SIG_LEN;

		  PRINTF("Sending first authentication message (size: %d)\n", buf_len);
		  uip_udp_packet_sendto(auth_conn, buf, buf_len,
						&server_ipaddr, UIP_HTONS(UDP_AUTH_PORT));

		  authentication_state = WAITING_FOR_RESPONSE;

		  /* start a timeout timer */
		  PRINTF("Starting authentication timer\n");
		  ctimer_set(&auth_timer, AUTH_TIMEOUT, reset_auth, NULL);
	  }

	  if(ev == tcpip_event) {
		  /* if this is an authentication response from the server */
		  PRINTF("Received a message (size %d)\n", uip_datalen());
		  if (authentication_state == WAITING_FOR_RESPONSE && \
			  uip_newdata() && \
			  uip_datalen() == AUTH_MSG_LEN) {
			  s_pub_certificate serv_cert;

			  PRINTF("It is an authentication message (disabling timeout timer)\n");
			  ctimer_stop(&auth_timer);

			  /* message stored in uip_appdata */
			  deserialize_pub_cert(uip_appdata, &serv_cert);

			  /* verify that the server certificate is valid */
			  if (verify_certificate(cacert, &serv_cert)) {
				  PRINTF("Server certificate is not trusted\n");
				  goto auth_fail;
			  }

			  if (certificate_ecdsa_verify(&serv_cert,
										   &((uint8_t *) uip_appdata)[PUB_CERT_SIZE], /* this is the point d'.G */
										   2*NUMBYTES,
										   &((uint8_t *) uip_appdata)[PUB_CERT_SIZE + 2 * NUMBYTES] /* this is the signature */
										   )) {
				  PRINTF("Signature does not match\n");
				  goto auth_fail;
			  } else {
				  PRINTF("Signature d'.G is valid\n");
			  }

			  /* compute d.d'.G (this is the shared secret) */
			  ecc_ecdh_from_network(secret, &((uint8_t * ) uip_appdata)[PUB_CERT_SIZE], shared_secret);

			  /* derive a longer key */
			  ecc_ecdh_derive_key(shared_secret, key);


			  PRINTF("Authentication succeeded\n");
			  authentication_state = AUTHENTICATED;
			  break;
auth_fail:
			  authentication_state = UNAUTHENTICATED;
			  continue;
		  }
	  }
	  PROCESS_YIELD();
  }

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

	if(authentication_state == AUTHENTICATED && etimer_expired(&periodic)) {
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
