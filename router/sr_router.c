/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  struct sr_ethernet_hdr* e_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);

  e_hdr = (struct sr_ethernet_hdr*)packet;

  printf("---->> Interface %s<----\n",interface);
  if (e_hdr->ether_type == htons(ethertype_arp))
  {
	struct sr_arp_hdr* a_hdr;
	a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

	printf("---->> Packet type ARP %u, %u<----\n",(unsigned)htons(e_hdr->ether_type), (unsigned)e_hdr->ether_type);
	printf("---->> An ARP packet protocol type %u, %u <----\n", a_hdr->ar_pro, htons(a_hdr->ar_pro));

	/*ARP request to me*/
	if(a_hdr->ar_op == htons(arp_op_request) )
	{
		/*Construct an ARP reply and send it back*/
		struct sr_ethernet_hdr* reply_packet_ethernet_header = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
		struct sr_arp_hdr* reply_packet_arp_header = ((struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr)));

		/*Ethernet header - Destination Address*/
		int i;
		for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			reply_packet_ethernet_header->ether_dhost[i] = e_hdr->ether_shost[i];
		}

		/*Ethernet header - Source Address*/
		for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			reply_packet_ethernet_header->ether_shost[i] = ((uint8_t)iface->addr[i]);
		}

		/*Ethernet header - Type*/
		reply_packet_ethernet_header->ether_type = e_hdr->ether_type;

		/*ARP header - Hardware type*/
		reply_packet_arp_header->ar_hrd = a_hdr->ar_hrd;

		/*ARP header - Protocol type*/
		reply_packet_arp_header->ar_pro = a_hdr->ar_pro;

		/*ARP header - Hardware address length*/
		reply_packet_arp_header->ar_hln = a_hdr->ar_hln;

		/*ARP header - Protocol address length*/
		reply_packet_arp_header->ar_pln = a_hdr->ar_pln;

		/*ARP header - Opcode*/
		reply_packet_arp_header->ar_op = htons(arp_op_reply);

		/*ARP header - Source hardware address*/
		for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			reply_packet_arp_header->ar_sha[i] = iface->addr[i];
		}

		/*ARP header - Source protocol address*/
		reply_packet_arp_header->ar_sip = a_hdr->ar_tip;

		/*ARP header - Destination hardware address*/
		for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			reply_packet_arp_header->ar_tha[i] = a_hdr->ar_sha[i];
		}

		/*ARP header - Destination protocol address*/
		reply_packet_arp_header->ar_tip = a_hdr->ar_sip;

		/*Create packet*/
		uint8_t* reply_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)));
		memcpy(reply_packet, reply_packet_ethernet_header, sizeof(struct sr_ethernet_hdr));
		memcpy(reply_packet + sizeof(struct sr_ethernet_hdr), reply_packet_arp_header, sizeof(struct sr_arp_hdr));

		/*Send packet*/
		sr_send_packet(sr, reply_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), iface->name);

		free(reply_packet_ethernet_header);
		free(reply_packet_arp_header);
		free(reply_packet);
	}

  }
  else
  {
	printf("---->> Packet type IP<----\n");
	struct sr_ip_hdr* ip_hdr;
	ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
	print_hdr_ip((uint8_t*)ip_hdr);

	/*Check packet checksum*/
	if(ip_hdr->ip_sum != cksum(ip_hdr, 20))
	{
		printf("---->> Checksum not good<----\n");

	}
	else
	{
		printf("---->> Checksum good<----\n");

	}

	/*Check TTL*/

	/* If ICMP
	*
	* Echo reply (type 0) It's for me
	* Destination net unreachable (type 3, code 0) Not for me -> Not match
	* Destination host unreachable (type 3, code 1) Not for me -> Match -> Miss -> Resent > 5 times
	* Port unreachable (type 3, code 3) It's for me
	* Time exceeded (type 11, code 0) It's for me && Not for me
	*
	* */




  }

}/* end sr_ForwardPacket */

