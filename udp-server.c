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
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/uip.h"
#include "net/rpl/rpl.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "certificate.h"

#if DOMAIN_PARAMS != SECP192K1
#error "Domain parameter does not match"
#endif


#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define UDP_AUTH_PORT   4242

#define UDP_EXAMPLE_ID  190

#define AUTH_MSG_LEN        (PUB_CERT_SIZE + 2*NUMBYTES + SIG_LEN)

static struct uip_udp_conn *server_conn;
static struct uip_udp_conn *auth_conn;
static s_certificate * cert;
static s_pub_certificate * cacert;

uint8_t raw_cacert [144] = {0x00, 0x00, 0x00, 0x00, 0x28, 0x17, 0xB0, 0xD5, 0xAF, 0x3A, 0x2E, 0xED, 0x04, 0x05, 0x22, 0x29, 0x83, 0x81, 0x77, 0xCC, 0x47, 0x57, 0xD7, 0x62, 0x37, 0xA0, 0xE9, 0xA3, 0x00, 0x00, 0x00, 0x00, 0xB7, 0x29, 0xF3, 0xD0, 0xE5, 0x77, 0x28, 0x96, 0x31, 0xAF, 0x00, 0xE2, 0x38, 0xFF, 0x09, 0xD8, 0xC8, 0x43, 0xE0, 0xC8, 0x90, 0xEA, 0x4F, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t raw_cert [172] = {0x00, 0x00, 0x00, 0x00, 0xD1, 0xC1, 0x60, 0xEC, 0xDB, 0x7B, 0xF8, 0xDE, 0x64, 0xD6, 0xF1, 0x1D, 0x1E, 0xFC, 0x11, 0x29, 0xB6, 0xCD, 0x65, 0xA5, 0x59, 0xD7, 0x27, 0x09, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x0B, 0x2C, 0x8E, 0x35, 0x4C, 0xF5, 0xDC, 0xCA, 0xBA, 0x63, 0xC0, 0x3D, 0x39, 0x7A, 0x4C, 0x45, 0xDC, 0xC3, 0x68, 0xE4, 0x9D, 0xB4, 0x49, 0x2D, 0x02, 0xDD, 0xCC, 0x19, 0xCC, 0x9B, 0xEF, 0xEE, 0x76, 0x21, 0x5A, 0xEE, 0xFD, 0x11, 0xE1, 0xB5, 0xA4, 0x48, 0x11, 0x15, 0x8E, 0xFD, 0xD4, 0xAA, 0xB6, 0xDC, 0xBB, 0xEF, 0x64, 0xED, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x48, 0xBA, 0xFF, 0xEA, 0x87, 0x70, 0xD5, 0xAD, 0xA5, 0x4E, 0xE1, 0xE8, 0xE1, 0xC6, 0x59, 0x2D, 0x3E, 0xD4, 0x09, 0x61, 0x23, 0xF5, 0x6F, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x93, 0xDF, 0xCD, 0x52, 0x1E, 0x5E, 0x8C, 0x29, 0x4D, 0x3A, 0xFD, 0xD7, 0x29, 0x25, 0x05, 0x9C, 0xFA, 0x59, 0x53, 0xC3, 0xB8, 0xBA, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0xEA, 0xA0, 0x22, 0x79, 0x61};

enum auth_state {
	UNAUTHENTICATED = 0,
	WAITING_FOR_RESPONSE,
	AUTHENTICATED
};

static enum auth_state client_authentication_state = UNAUTHENTICATED;


/*---------------------------------------------------------------------------*/
PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *appdata;

  if(uip_newdata() &&
	 UIP_IP_BUF->proto == 17 && /* this is a UDP packet for the UDP application */
	 ((struct uip_udpip_hdr *) uip_buf)->destport == UIP_HTONS(UDP_SERVER_PORT)) {
    appdata = (char *)uip_appdata;
    appdata[uip_datalen()] = 0;
    PRINTF("DATA recv '%s' from ", appdata);
    PRINTF("%d",
           UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]);
    PRINTF("\n");
#if SERVER_REPLY
    PRINTF("DATA sending reply\n");
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    uip_udp_packet_send(server_conn, "Reply", sizeof("Reply"));
    uip_create_unspecified(&server_conn->ripaddr);
#endif
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED) {
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
PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;
  static NN_DIGIT secret[NUMWORDS];
  static uint8_t point[2*NUMBYTES], shared_secret[2*NUMBYTES];
  static uint8_t key[SHA256_DIGEST_LENGTH];

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  SENSORS_ACTIVATE(button_sensor);

  PRINTF("UDP server started\n");

  init_crypto();

#if UIP_CONF_ROUTER
/* The choice of server address determines its 6LoPAN header compression.
 * Obviously the choice made here must also be selected in udp-client.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 * Note Wireshark's IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from link local (MAC) address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
#endif

  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
#endif /* UIP_CONF_ROUTER */
  
  print_local_addresses();

  /* new connection for running the authentication */
  auth_conn = udp_new(NULL, UIP_HTONS(UDP_AUTH_PORT), NULL);
  if (auth_conn == NULL) {
	PRINTF("No UDP connection available, exiting the process!\n");
	PROCESS_EXIT();
  }
  udp_bind(auth_conn, UIP_HTONS(UDP_AUTH_PORT));

  /* The data sink runs with a 100% duty cycle in order to ensure high 
     packet reception rates. */
  NETSTACK_MAC.off(1);

  /* authenticate a single client (yes, this is not flexible) */
  while(client_authentication_state != AUTHENTICATED) {
	  PRINTF("Waiting for an authentication request message\n");
	  PROCESS_YIELD();

	  if(ev == tcpip_event) {
		  /* if this is an authentication message from the client */
		  if (uip_newdata() && \
			  uip_datalen() == AUTH_MSG_LEN) {
			  s_pub_certificate client_cert;
			  uint8_t buf[AUTH_MSG_LEN];
			  int buf_len = 0;
			  int i;
			  memset(&client_cert, sizeof(client_cert), 0);

			  PRINTF("Received authentication message from: ");
			  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
			  PRINTF("\n");

			  /* message stored in uip_appdata */
			  deserialize_pub_cert(uip_appdata, &client_cert);

			  /* verify that the server certificate is valid */
			  if (verify_certificate(cacert, &client_cert)) {
				  PRINTF("Client certificate is not trusted\n");
				  goto auth_fail;
			  }

			  if (certificate_ecdsa_verify(&client_cert,
										   &((uint8_t *) uip_appdata)[PUB_CERT_SIZE], /* this is the point d'.G */
										   2*NUMBYTES,
										   &((uint8_t *) uip_appdata)[PUB_CERT_SIZE + 2 * NUMBYTES] /* this is the signature */
										   )) {
				  PRINTF("Signature does not match\n");
				  goto auth_fail;
			  } else {
				  PRINTF("Signature d'.G is valid\n");
			  }
			  /* compute the local ECDH secret */
			  ecc_ecdh_from_host(secret, point);

			  /* compute d.d'.G (this is the shared secret) */
			  ecc_ecdh_from_network(secret, &((uint8_t * ) uip_appdata)[PUB_CERT_SIZE], shared_secret);

			  /* derive a longer key */
			  ecc_ecdh_derive_key(shared_secret, key);

			  /* preparring the response message */

			 /* copy the server's certificate */
			  serialize_pub_cert(&cert->pub_cert, buf);
			  buf_len += PUB_CERT_SIZE;
			  /* copy the randomly generated point on the curve */
			  memcpy(buf + buf_len, point, sizeof(point));
			  buf_len += sizeof(point);
			  /* add the signature */
			  certificate_ecdsa_sign(cert, point, sizeof(point), buf+buf_len);
			  buf_len += SIG_LEN;

			  PRINTF("Sending authentication response message\n");
			  uip_udp_packet_sendto(auth_conn, buf, buf_len,
									&UIP_IP_BUF->srcipaddr,
									UIP_HTONS(UDP_AUTH_PORT));


			  PRINTF("Authentication succeeded\n");
			  client_authentication_state = AUTHENTICATED;
			  break;
auth_fail:
			  client_authentication_state = UNAUTHENTICATED;
		  }
	  }
  }

  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
  if(server_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

  PRINTF("Created a server connection with remote address ");
  PRINT6ADDR(&server_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
         UIP_HTONS(server_conn->rport));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == sensors_event && data == &button_sensor) {
	  PRINTF("Initiating global repair\n");
      rpl_repair_root(RPL_DEFAULT_INSTANCE);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
