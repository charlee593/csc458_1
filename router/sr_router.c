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

	if(ip_hdr->ip_ttl <=1)
	{
		printf("---->> Send ICMP (type 11, code 0)<----\n");
		send_icmp(sr, packet, iface->name, 11, 0);
	}

	/*Check if it is for me - check all interfaces in router*/
	struct sr_if* curr_if = sr->if_list;
	while(curr_if != NULL)
	{
		if (ip_hdr->ip_dst == curr_if->ip)
		{
			printf("---->> Its for me<----\n");
		}
		curr_if = curr_if->next;
	}

	/*It is for not me*/
	if(curr_if == NULL)
	{
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
struct sr_if* lpm(struct sr_instance *sr, uint32_t ip)
{
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

/*
	Generate the following ICMP messages (including the ICMP header checksum) in response to the sending host under the following conditions:

	Echo reply (type 0)
	Sent in response to an echo request (ping) to one of the router’s interfaces. (This is only for echo requests to any of the router’s IPs. An echo request sent elsewhere should be forwarded to the next hop address as usual.)
	Destination net unreachable (type 3, code 0)
	** Sent if there is a non-existent route to the destination IP (no matching entry in routing table when forwarding an IP packet).
	Destination host unreachable (type 3, code 1)
	** Sent if five ARP requests were sent to the next-hop IP without a response.
	Port unreachable (type 3, code 3)
	** Sent if an IP packet containing a UDP or TCP payload is sent to one of the router’s interfaces. This is needed for traceroute to work.
	Time exceeded (type 11, code 0)
	** Sent if an IP packet is discarded during processing because the TTL field is 0. This is also needed for traceroute to work.
	The source address of an ICMP message can be the source address of any of the incoming interfaces, as specified in RFC 792.
	As mentioned above, the only incoming ICMP message destined towards the router’s IPs that you have to explicitly process are ICMP echo requests.
	You may want to create additional structs for ICMP messages for convenience, but make sure to use the packed attribute so that the compiler doesn’t try to align the fields in the struct to word boundaries:
*/
void send_icmp(struct sr_instance *sr, uint8_t * received_packet, char* from_interface, uint8_t type, uint8_t code)
{
	struct sr_ethernet_hdr* received_packet_e_hdr = (struct sr_ethernet_hdr*)received_packet;
	struct sr_ip_hdr* received_packet_ip_hdr = (struct sr_ip_hdr*)(received_packet + sizeof(struct sr_ethernet_hdr));

	struct sr_ethernet_hdr* icmp_packet_ethernet_header = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
	struct sr_ip_hdr* icmp_packet_ip_header = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));
	struct sr_if* iface = sr_get_interface(sr, from_interface);

	/*Ethernet destination address*/
	memcpy(icmp_packet_ethernet_header->ether_dhost, received_packet_e_hdr->ether_shost, ETHER_ADDR_LEN);
	/*Ethernet source Address*/
	memcpy(icmp_packet_ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
	/*Ethernet header - Type*/
	icmp_packet_ethernet_header->ether_type = htons(ethertype_arp);

	/*ip header - version*/
	icmp_packet_ip_header->ip_hl = 5;
	/*ip header - ihl*/
	icmp_packet_ip_header->ip_v = 4;
	/*ip header - Differentiated services*/
	icmp_packet_ip_header->ip_tos = htonl(0);


	if(type == 3)
	{
		struct sr_icmp_t3_hdr_t* icmp_packet_icmp_header = ((struct sr_icmp_t3_hdr_t*)malloc(sizeof(struct sr_icmp_t3_hdr)));
	}
	else
	{
		/*Time exceeded (type 11, code 0)*/
		struct sr_icmp_hdr* icmp_packet_icmp_header = ((struct sr_icmp_hdr*)malloc(sizeof(struct sr_icmp_hdr)));

		/*ip header - total length*/
		icmp_packet_ip_header->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr));
		/*ip header - identification*/
		icmp_packet_ip_header->ip_id = 0;
		/*ip header - fragment offset field */
		icmp_packet_ip_header->ip_off = 0;
		/*ip header -  time to live*/
		icmp_packet_ip_header->ip_ttl = 100;
		/*ip header -  protocol*/
		icmp_packet_ip_header->ip_p = 1;
		/*ip header -  checksum*/
		icmp_packet_ip_header->ip_sum = 0;
		/*ip header -  source and dest address */
		icmp_packet_ip_header->ip_src = iface->ip;
		icmp_packet_ip_header->ip_dst = received_packet_ip_hdr->ip_src;
		/*ip header -  checksum*/
		icmp_packet_ip_header->ip_sum = cksum(icmp_packet_ip_header, sizeof(struct sr_ip_hdr));

		/*icmp header -  type*/
		icmp_packet_icmp_header->icmp_type = type;
		/*icmp header -  code*/
		icmp_packet_icmp_header->icmp_code = code;
		/*icmp header -  checksum*/
		icmp_packet_icmp_header->icmp_sum = 0;
		icmp_packet_icmp_header->icmp_sum = cksum(icmp_packet_icmp_header, sizeof(struct sr_icmp_hdr));

		/*Create packet*/
		uint8_t* icmp_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr)));
		memcpy(icmp_packet, icmp_packet_ethernet_header, sizeof(struct sr_ethernet_hdr));
		memcpy(icmp_packet + sizeof(struct sr_ethernet_hdr), icmp_packet_ip_header, sizeof(struct sr_ip_hdr));
		memcpy(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_icmp_hdr), icmp_packet_icmp_header, sizeof(struct sr_icmp_hdr));

		/*Send packet*/
		sr_send_packet(sr, icmp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr), iface->name);

		free(icmp_packet_ethernet_header);
		free(icmp_packet_ip_header);
		free(icmp_packet_icmp_header);
		free(icmp_packet);
	}




}/* end send_icmp */
