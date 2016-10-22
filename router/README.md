# [Programming Assignment 1 - Simple Router](http://www.cs.toronto.edu/~yganjali/courses/csc458/assignments/simple-router/)

### Introduction
"In this assignment you will be writing a simple router with a static routing table. Your router will receive raw Ethernet frames. It will process the packets just like a real router, then forward them to the correct outgoing interface. We’ll make sure you receive the Ethernet frames; your job is to create the forwarding logic so packets go to the correct interface.

Your router will route real packets from an emulated host (client) to two emulated application servers (http server 1 and 2) sitting behind your router. The application servers are each running an HTTP server. When you have finished the forwarding path of your router, you should be able to access these servers using regular client software. In addition, you should be able to ping and traceroute to and through a functioning Internet router."

### Implemented Functions

Functions to handle packets are under sr_router.c file. The longest prefix match function is also under sr_router.c.

``` c
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

void reply_to_arp_req(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr, struct sr_arp_hdr* a_hdr, struct sr_if* iface);

void process_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface);

void handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, struct sr_ip_hdr* ip_hdr, struct sr_if* iface);

void handle_ip_packet_to_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_ip_hdr* ip_hdr, struct sr_if* iface);

void send_echo_reply(struct sr_instance* sr, uint8_t* received_frame, char* from_interface);

struct sr_if* lpm(struct sr_instance *sr, struct in_addr target_ip);

void send_icmp(struct sr_instance *sr, uint8_t * received_packet, char* from_interface, uint8_t type, uint8_t code);
```

Functions to handle queued packets waiting for ARP reply are under sr_arpcache.c file.

``` c
void handle_arpreq(struct sr_arpreq *req, struct sr_instance *sr);

void sr_arpcache_sweepreqs(struct sr_instance *sr);
```
