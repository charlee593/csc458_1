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
	else if(a_hdr->ar_op == htons(arp_op_reply))
	{
		/*# When servicing an arp reply that gives us an IP->MAC mapping
		req = arpcache_insert(ip, mac)

		if req:
			send all packets on the req->packets linked list
			arpreq_destroy(req)*/
		struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, a_hdr->ar_sha, a_hdr->ar_sip);
		if(req)
		{
			struct sr_packet* curr_packets_to_send = req->packets;

			printf("---->> ARP Reply send outstanding packet<----\n");
			while(curr_packets_to_send != NULL)
			{
				struct sr_ethernet_hdr* curr_e_hdr = (struct sr_ethernet_hdr*)curr_packets_to_send->buf;

				/*Ethernet header - Destination Address*/
				memcpy(curr_e_hdr->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);

				/*Ethernet header - Source Address*/
				memcpy(curr_e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

				/*Send packet*/
				sr_send_packet(sr, curr_packets_to_send->buf, curr_packets_to_send->len, interface);

				curr_packets_to_send = curr_packets_to_send->next;
			}
			sr_arpreq_destroy(&sr->cache, req);
		}
	}
	else
	{
		printf("---->> ARP Packet that is not reply or request<----\n");
		return;
	}

  }
  else
  {
	/* If ICMP
	*
	* Echo reply (type 0) It's for me
	* Destination net unreachable (type 3, code 0) Not for me -> Not match
	* Destination host unreachable (type 3, code 1) Not for me -> Match -> Miss -> Resent > 5 times
	* Port unreachable (type 3, code 3) It's for me
	* Time exceeded (type 11, code 0) It's for me && Not for me
	*
	* */
	printf("---->> Packet type IP<----\n");
	struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
	print_hdr_ip((uint8_t*)ip_hdr);

	/*Check packet checksum*/
	uint16_t ip_checksum_temp = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if(ip_checksum_temp != cksum(ip_hdr, sizeof(struct sr_ip_hdr)))
	{
		printf("---->> Checksum not good %u<----\n",cksum(ip_hdr, sizeof(struct sr_ip_hdr)));
		return;
	}
	ip_hdr->ip_sum = ip_checksum_temp;

	/*Check if it is for me*/
	struct sr_if* curr_if = sr->if_list;
	while(curr_if != NULL)
	{
		if (ip_hdr->ip_dst == curr_if->ip)
		{
			/*Check TTL*/
			if(ip_hdr->ip_ttl <=1)
			{
				printf("---->> Send ICMP (type 11, code 0)<----\n");
			}
			printf("---->> Its for me<----\n");
		}
		curr_if = curr_if->next;
	}

	/*It is for not me*/
	if(curr_if == NULL)
	{
		if(ip_hdr->ip_ttl <=1)
		{
			printf("---->> Send ICMP (type 11, code 0)<----\n");
		}
		printf("---->> Its for not me<----\n");

		/*Decrement the TTL by 1, and recompute the packet checksum over the modified header.*/
		ip_hdr->ip_ttl--;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

		struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
		if(entry)
		{
			printf("---->> Found mac add in cache, forward packet<----\n");

			/*Forward packet*/
			struct sr_if* match_iface = lpm(sr, ip_hdr->ip_dst);
			if(match_iface)
			{
				/*Swap ethernet address*/
				memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
				/*Ethernet header - Source Address*/
				memcpy(e_hdr->ether_shost, match_iface->addr, ETHER_ADDR_LEN);
				/*Send packet*/
				sr_send_packet(sr, packet, len, match_iface->name);
			}
			free(entry);
		}
		else
		{
			struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
			handle_arpreq(req, sr);
		}
	}
  }

}/* end sr_ForwardPacket */

/*
  Check routing table, perform LPM
*/
struct sr_if* lpm(struct sr_instance *sr, uint32_t ip) {
	/*Find match interface in routing table LPM*/
	struct sr_rt* curr_routing_entry = sr->routing_table;
	while(curr_routing_entry != NULL)
	{
		if (curr_routing_entry->dest.s_addr == ip)
		{
			return sr_get_interface(sr, curr_routing_entry->interface);
		}
		curr_routing_entry = curr_routing_entry->next;
	}
	return NULL;
}/* end lpm */
