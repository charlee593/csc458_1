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

    /* Check for minimum frame size */
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        printf("---->> Received ethernet frame that is too short. <----\n");
        return;
    }

    printf("*** -> Received packet of length %d \n",len);

    struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
    struct sr_if* iface = sr_get_interface(sr, interface);

    printf("---->> Interface %s<----\n", interface);

    /* Check if Ethertype is ARP */
    if (e_hdr->ether_type == htons(ethertype_arp))
    {
        /* Get the ARP header */
        struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

        printf("---->> Packet type ARP %u, %u<----\n",(unsigned)htons(e_hdr->ether_type), (unsigned)e_hdr->ether_type);
        printf("---->> An ARP packet protocol type %u, %u <----\n", arp_hdr->ar_pro, htons(arp_hdr->ar_pro));

        /* ARP request to me */
        if(arp_hdr->ar_op == htons(arp_op_request))
        {
            reply_to_arp_req(sr, e_hdr, arp_hdr, iface);
        }
        /* ARP reply */
        else if(arp_hdr->ar_op == htons(arp_op_reply))
        {
            process_arp_reply(sr, arp_hdr, iface);
        }
        else
        {
            printf("---->> Received ARP Packet that is neither reply nor request <----\n");
        }
    }
    /* Check if Ethertype is IP */
    else if (e_hdr->ether_type == htons(ethertype_ip))
    {
        printf("---->> Packet type IP <----\n");
        struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

        /* Check for minimum total length of IP header */
        if(ip_hdr->ip_hl < IP_IHL)
        {
            printf("---->> IP header is smaller than the minimum size allowed <----\n");
            return;
        }

        /* Check packet checksum */
        uint16_t ip_checksum_temp = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        if(ip_checksum_temp != cksum(ip_hdr, sizeof(struct sr_ip_hdr)))
        {
            printf("---->> IP header checksum is incorrect %u <----\n", cksum(ip_hdr, sizeof(struct sr_ip_hdr)));
            return;
        }
        ip_hdr->ip_sum = ip_checksum_temp;



        /* Check if it is for me - find interfaces name */
        struct sr_if* curr_if = sr->if_list;
        while(curr_if != NULL)
        {
            if (ip_hdr->ip_dst == curr_if->ip)
            {
                printf("---->> Received IP packet for me <----\n");

                handle_ip_packet_for_router(sr, packet, ip_hdr, iface);

                return;
            }
            curr_if = curr_if->next;
        }

        /* It is not for me */
        if(curr_if == NULL)
        {
            printf("---->> It's not for me <----\n");

            handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);
        }
    }
    else
    {
        printf("---->> Received Ethernet frame that contains neither IP packet nor ARP packet <----\n");
    }
} /* end sr_handlepacket */

void reply_to_arp_req(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface)
{
    /* Construct an ARP reply and send it back */
    struct sr_ethernet_hdr* reply_packet_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_arp_hdr* reply_packet_arp_hdr = ((struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr)));

    /* Ethernet header - Destination Address */
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_eth_hdr->ether_dhost[i] = e_hdr->ether_shost[i];

    /* Ethernet header - Source Address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    reply_packet_eth_hdr->ether_type = htons(ethertype_arp);


    /* ARP header - Hardware type */
    reply_packet_arp_hdr->ar_hrd = arp_hdr->ar_hrd;

    /* ARP header - Protocol type */
    reply_packet_arp_hdr->ar_pro = arp_hdr->ar_pro;

    /* ARP header - Hardware address length */
    reply_packet_arp_hdr->ar_hln = arp_hdr->ar_hln;

    /* ARP header - Protocol address length */
    reply_packet_arp_hdr->ar_pln = arp_hdr->ar_pln;

    /* ARP header - Opcode */
    reply_packet_arp_hdr->ar_op = htons(arp_op_reply);

    /* ARP header - Source hardware address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_arp_hdr->ar_sha[i] = iface->addr[i];

    /* ARP header - Source protocol address */
    reply_packet_arp_hdr->ar_sip = iface->ip;                                                       /*arp_hdr->ar_tip   ???  */

    /* ARP header - Destination hardware address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];

    /* ARP header - Destination protocol address */
    reply_packet_arp_hdr->ar_tip = arp_hdr->ar_sip;

    /* Create packet */
    uint8_t* reply_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)));
    memcpy(reply_packet, reply_packet_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(reply_packet + sizeof(struct sr_ethernet_hdr), reply_packet_arp_hdr, sizeof(struct sr_arp_hdr));

    /* Send packet */
    sr_send_packet(sr, reply_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), iface->name);

    free(reply_packet_eth_hdr);
    free(reply_packet_arp_hdr);
    free(reply_packet);
} /* end reply_to_arp_req */

void process_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface)
{
    /* When servicing an arp reply that gives us an IP->MAC mapping
       req = arpcache_insert(ip, mac)

    if req:
    send all packets on the req->packets linked list
    arpreq_destroy(req) */
    struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if(req)
    {
        struct sr_packet* curr_packet_to_send = req->packets;

        printf("---->> ARP Reply send outstanding packet <----\n");
        while(curr_packet_to_send != NULL)
        {
            struct sr_ethernet_hdr* curr_e_hdr = (struct sr_ethernet_hdr*)curr_packet_to_send->buf;

            /* Ethernet header - Destination Address */
            /*memcpy(curr_e_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);*/
            int i;
            for(i = 0; i < ETHER_ADDR_LEN; i++)
                curr_e_hdr->ether_dhost[i] = arp_hdr->ar_sha[i];

            /* Ethernet header - Source Address */
            /*memcpy(curr_e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);*/
            for(i = 0; i < ETHER_ADDR_LEN; i++)
                curr_e_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

            /* Send packet */
            sr_send_packet(sr, curr_packet_to_send->buf, curr_packet_to_send->len, iface->name);

            curr_packet_to_send = curr_packet_to_send->next;
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
}

void handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, struct sr_ip_hdr* ip_hdr, struct sr_if* iface)
{
    /*https://tools.ietf.org/html/rfc1812#section-4.2.2.9*/
    /*if(ip_hdr->ip_ttl < 1)
    {
        printf("---->> Send ICMP (type 11, code 0) <------------------------------\n");
        send_icmp(sr, packet, iface->name, 11, 0);
        return;
    }*/

    /* Received ICMP packet */
    if(ip_hdr->ip_p == ip_protocol_icmp)
    {
        struct sr_icmp_t0_hdr* icmp_hdr = (struct sr_icmp_t0_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        /* Check ICMP packet checksum */
        uint16_t icmp_sum_temp = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        int icmp_len = ntohs(ip_hdr->ip_len) - IP_IHL_BYTES;
        if(icmp_sum_temp != cksum(icmp_hdr, icmp_len))
        {
            printf("---->> Incorrect checksum of ICMP packet %u <----\n", cksum(icmp_hdr, icmp_len));
            return;
        }
        icmp_hdr->icmp_sum = icmp_sum_temp;

        /* Received Echo request */
        if(icmp_hdr->icmp_type == icmp_type_echo_req)
        {
            /* Check minimum total length of the IP packet */
            if(ntohs(ip_hdr->ip_len) < (4 * ip_hdr->ip_hl + ICMP_ECHO_HDR_SIZE))
            {
                printf("---->> Total length of IP packet is too small for an echo request <----\n");
                return;
            }

            /* Send Echo reply */
            /*send_icmp(sr, packet, iface->name, 0, 0);*/
            send_echo_reply(sr, packet, iface->name);
        }
        return;
    }

    /* Received ICMP packet UDP or TCP */
    if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
    {
        /* Send ICMP port unreachable */
        send_icmp(sr, packet, iface->name, 3, 3);
    }
}

void handle_ip_packet_to_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_ip_hdr* ip_hdr, struct sr_if* iface)
{
    if(ip_hdr->ip_ttl <= 1)
    {
        printf("---->> Send ICMP (type 11, code 0) <----\n");
        send_icmp(sr, packet, iface->name, 11, 0);
        return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

    /* Forward packet */
    struct sr_if* match_iface = lpm(sr, ntohl(ip_hdr->ip_dst));
    if(!match_iface)
    {
        /* Send Destination net unreachable */
        send_icmp(sr, packet, iface->name, 3, 0);
        return;
    }

    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if(entry)
    {
        printf("---->> Found mac add in cache, forward packet<----\n");

/*                 Forward packet */

        struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;

        /* Swap ethernet address */
        memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        /* Ethernet header - Source Address */
        memcpy(e_hdr->ether_shost, match_iface->addr, ETHER_ADDR_LEN);
        /* Send packet */
        sr_send_packet(sr, packet, len, match_iface->name);

        free(entry);
    }
    else
    {
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, iface->name);
        handle_arpreq(req, sr);
    }
}

void send_echo_reply(struct sr_instance* sr, uint8_t* received_frame, char* from_interface)
{
    struct sr_ethernet_hdr* received_eth_hdr = (struct sr_ethernet_hdr*)received_frame;
    struct sr_ip_hdr* received_ip_hdr = (struct sr_ip_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr));
    struct sr_icmp_t0_hdr* received_icmp_hdr = (struct sr_icmp_t0_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

    struct sr_ethernet_hdr* reply_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_ip_hdr* reply_ip_hdr = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));
    struct sr_icmp_t0_hdr* reply_icmp_hdr = ((struct sr_icmp_t0_hdr*)malloc(sizeof(struct sr_icmp_t0_hdr)));
    struct sr_if* iface = sr_get_interface(sr, from_interface);

    /* Ethernet destination address */
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_dhost[i] = received_eth_hdr->ether_shost[i];

    /* Ethernet source address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    reply_eth_hdr->ether_type = htons(ethertype_ip);

    /* IP header - ihl */
    reply_ip_hdr->ip_v = IPv4_VERSION;

    /* IP header - version */
    reply_ip_hdr->ip_hl = IP_IHL;

    /* IP header - Differentiated services */
    reply_ip_hdr->ip_tos = 0;

    /* IP header - total length */
    reply_ip_hdr->ip_len = received_ip_hdr->ip_len;

    /* IP header - identification */
    reply_ip_hdr->ip_id = IP_ID;

    /* IP header - fragment offset field */
    reply_ip_hdr->ip_off = htons(IP_DF);

    /* IP header -  time to live */
    reply_ip_hdr->ip_ttl = IP_INIT_TTL;

    /* IP header - protocol */
    reply_ip_hdr->ip_p = ip_protocol_icmp;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = 0;

    /* IP header - source and dest addresses */
    reply_ip_hdr->ip_src = received_ip_hdr->ip_dst;                                                   /* DO LPM !!!!!!!!!! */
    reply_ip_hdr->ip_dst = received_ip_hdr->ip_src;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, IP_IHL_BYTES);

    /* ICMP header - type */
    reply_icmp_hdr->icmp_type = icmp_type_echo_reply;

    /* ICMP header - code */
    reply_icmp_hdr->icmp_code = 0;

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = 0;

    /* ICMP header - identifier */
    reply_icmp_hdr->icmp_id = received_icmp_hdr->icmp_id;

    /* ICMP header - sequence number */
    reply_icmp_hdr->icmp_seq_num = received_icmp_hdr->icmp_seq_num;

    /* ICMP header - data */
    memcpy(reply_icmp_hdr->data, received_icmp_hdr->data, ntohs(reply_ip_hdr->ip_len) - IP_IHL_BYTES - ICMP_ECHO_HDR_SIZE);

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, ntohs(reply_ip_hdr->ip_len) - IP_IHL_BYTES);

    /* Create packet */
    uint8_t* frame_to_send = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr)));
    memcpy(frame_to_send, reply_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr), reply_ip_hdr, sizeof(struct sr_ip_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), reply_icmp_hdr, sizeof(struct sr_icmp_t0_hdr));

    /* Send packet */
    sr_send_packet(sr, frame_to_send, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr), iface->name);

    free(reply_eth_hdr);
    free(reply_ip_hdr);
    free(reply_icmp_hdr);
    free(frame_to_send);
} /* end send_echo_reply */

/*
  Check routing table, perform LPM
*/
struct sr_if* lpm(struct sr_instance *sr, struct in_addr target_ip)
{
    /* Find match interface in routing table LPM */
    struct sr_rt* curr_rt_entry = sr->routing_table;
    int longest_match = -1;
    struct sr_if* result = NULL;

    while(curr_rt_entry != NULL)
    {
        /* Check if current routing table has longer mask than longest known so far */
        if(curr_rt_entry->mask.s_addr > longest_match)
        {
            /* Now check that we actually have a match */
            if((target_ip.s_addr & curr_rt_entry->mask.s_addr) ==
               (curr_rt_entry->dest.s_addr & curr_rt_entry->mask.s_addr))
            {
                longest_match = curr_rt_entry->mask.s_addr;
                result = sr_get_interface(sr, curr_rt_entry->interface);
            }
        }
        curr_rt_entry = curr_rt_entry->next;
    }
    return result;
}/* end lpm */

/*
    Generate the following ICMP messages (including the ICMP header checksum)
    in response to the sending host under the following conditions:

    Echo reply (type 0)
    ** Sent in response to an echo request (ping) to one of the router’s
       interfaces. (This is only for echo requests to any of the router’s IPs.
       An echo request sent elsewhere should be forwarded to the next hop
       address as usual).

    Destination net unreachable (type 3, code 0)
    ** Sent if there is a non-existent route to the destination IP
       (no matching entry in routing table when forwarding an IP packet).

	Destination host unreachable (type 3, code 1)
    ** Sent if five ARP requests were sent to the next-hop IP without a
       response.

	Port unreachable (type 3, code 3)
    ** Sent if an IP packet containing a UDP or TCP payload is sent to one
       of the router’s interfaces. This is needed for traceroute to work.

	Time exceeded (type 11, code 0)
    ** Sent if an IP packet is discarded during processing because the TTL
       field is 0. This is also needed for traceroute to work.

	The source address of an ICMP message can be the source address of any
	of the incoming interfaces, as specified in RFC 792.
	As mentioned above, the only incoming ICMP message destined towards the
	router’s IPs that you have to explicitly process are ICMP echo requests.
	You may want to create additional structs for ICMP messages for
	convenience, but make sure to use the packed attribute so that the
	compiler doesn’t try to align the fields in the struct to word boundaries.
*/
void send_icmp(struct sr_instance *sr, uint8_t * received_packet, char* from_interface, uint8_t type, uint8_t code)
{
    struct sr_ethernet_hdr* received_packet_e_hdr = (struct sr_ethernet_hdr*)received_packet;
    struct sr_ip_hdr* received_packet_ip_hdr = (struct sr_ip_hdr*)(received_packet + sizeof(struct sr_ethernet_hdr));

    struct sr_ethernet_hdr* icmp_packet_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_ip_hdr* icmp_packet_ip_hdr = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));
    struct sr_icmp_t3_hdr* icmp_packet_icmp_hdr = ((struct sr_icmp_t3_hdr*)malloc(sizeof(struct sr_icmp_t3_hdr)));
    struct sr_if* iface = sr_get_interface(sr, from_interface);

    if(iface == 0)
    {
        printf("---->> Interface %s not found. <----\n", from_interface);
        return;
    }

    /* Ethernet destination address */
    /*memcpy(icmp_packet_eth_hdr->ether_dhost, received_packet_e_hdr->ether_shost, ETHER_ADDR_LEN);*/
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        icmp_packet_eth_hdr->ether_dhost[i] = received_packet_e_hdr->ether_shost[i];

    /* Ethernet source address */
    /*memcpy(icmp_packet_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);*/
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        icmp_packet_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    icmp_packet_eth_hdr->ether_type = htons(ethertype_ip);

    /* IP header - version */
    icmp_packet_ip_hdr->ip_hl = 5;
    /* IP header - ihl */
    icmp_packet_ip_hdr->ip_v = 4;
    /* IP header - Differentiated services */
    icmp_packet_ip_hdr->ip_tos = htonl(0);
    /* IP header - total length */
    icmp_packet_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
    /* IP header - identification */
    icmp_packet_ip_hdr->ip_id = 0;
    /* IP header - fragment offset field */
    icmp_packet_ip_hdr->ip_off = 0;
    /* IP header -  time to live */
    if(type == 11)
    {
        icmp_packet_ip_hdr->ip_ttl = 100; 		/* Time exceeded (type 11, code 0) */
    }
    else
    {
        icmp_packet_ip_hdr->ip_ttl = 64;
    }
    /* IP header - protocol */
    icmp_packet_ip_hdr->ip_p = 1;
    /* IP header - checksum */
    icmp_packet_ip_hdr->ip_sum = 0;
    /* IP header - source and dest address */
    icmp_packet_ip_hdr->ip_src = iface->ip;
    icmp_packet_ip_hdr->ip_dst = received_packet_ip_hdr->ip_src;
    /* IP header - checksum */
    icmp_packet_ip_hdr->ip_sum = cksum(icmp_packet_ip_hdr, sizeof(struct sr_ip_hdr));

    /* ICMP header - type */
    icmp_packet_icmp_hdr->icmp_type = type;
    /* ICMP header - code */
    icmp_packet_icmp_hdr->icmp_code = code;
    /* ICMP header - checksum */
    icmp_packet_icmp_hdr->icmp_sum = 0;
    /* ICMP header - data */
    memcpy(icmp_packet_icmp_hdr->data, received_packet_ip_hdr, ICMP_DATA_SIZE);
    /* ICMP header - checksum */
    icmp_packet_icmp_hdr->icmp_sum = cksum(icmp_packet_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

    /* Create packet */
    uint8_t* icmp_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr)));
    memcpy(icmp_packet, icmp_packet_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(icmp_packet + sizeof(struct sr_ethernet_hdr), icmp_packet_ip_hdr, sizeof(struct sr_ip_hdr));
    memcpy(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_packet_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

    /* Send packet */
    sr_send_packet(sr, icmp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), iface->name);

    free(icmp_packet_eth_hdr);
    free(icmp_packet_ip_hdr);
    free(icmp_packet_icmp_hdr);
    free(icmp_packet);

}/* end send_icmp */
