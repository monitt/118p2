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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
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

int isRouterIp(struct sr_instance* sr,uint32_t dstip)
{
	struct sr_if* interface_p = sr->if_list;
	while(interface_p!=NULL)
	{
		if(interface_p->ip == dstip)
			return 1;
		interface_p = interface_p->next;
	}
	return 0;
}

uint32_t get_gw(struct sr_instance* sr,char * name)
{
	struct sr_rt* rt_p = sr->routing_table;
	for(;rt_p!=NULL;rt_p = rt_p->next)
	{
		int i;
		for(i=0;i<sr_IFACE_NAMELEN;i++)
		{
			if((*(name+i)) != (*((rt_p->interface)+i)))
				break;
		}
		if(i == sr_IFACE_NAMELEN)
			return rt_p->gw.s_addr;
	}
	return 0;
}

uint8_t* newArpPacket(unsigned short arp_op, unsigned char *arp_sha, uint32_t arp_sip, unsigned char *arp_tha, uint32_t arp_tip)
{
	/*ethernet header + arp header*/
	uint8_t* pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) pkt;
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (pkt+ sizeof(sr_ethernet_hdr_t));
	
	/*define ethernet header*/
	memcpy(ethernet_hdr->ether_dhost, arp_tha, ETHER_ADDR_LEN);
	memcpy(ethernet_hdr->ether_shost, arp_sha, ETHER_ADDR_LEN);
	ethernet_hdr->ether_type = htons(ethertype_arp);

	/*define arp header*/
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(arp_op);
	memcpy(arp_hdr->ar_sha, arp_sha, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = arp_sip;
	memcpy(arp_hdr->ar_tha, arp_sha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = arp_tip;

	return pkt;
}

void handleArpPacket(struct sr_instance* sr, sr_arp_hdr_t* header, unsigned int len, struct sr_if *interface)
{
	/*request error*/
	if ((header->ar_hrd != htons(arp_hrd_ethernet)) || (header->ar_pro != htons(ethertype_ip)) || (header->ar_hln != ETHER_ADDR_LEN) || (header->ar_op != htons(arp_op_request) && header->ar_op != htons(arp_op_reply))){
		fprintf(stderr, "Bad request.\n");
		return;
	}
	/*ARP request*/
	else if ((interface->ip == header->ar_tip) && (header->ar_op == htons(arp_op_request)))	{
		uint8_t* buf = newArpPacket(arp_op_reply, interface->addr, header->ar_tip, header->ar_sha, header->ar_sip);
		unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
		sr_send_packet(sr,buf, len, interface->name);
		fprintf(stderr, "IP:\n");
		print_addr_ip_int(interface->ip);
		fprintf(stderr, "Headers:\n");
		print_hdrs(buf,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
		free(buf);
	}
	/*ARP reply*/
	else if ((interface->ip == header->ar_tip) && (header->ar_op == htons(arp_op_reply)))	{	
		struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, header->ar_sha, header->ar_sip);
		do	{
			struct sr_packet* pack = request->packets;
			memcpy(((sr_ethernet_hdr_t*)pack->buf)->ether_shost, header->ar_tha, ETHER_ADDR_LEN);
			memcpy(((sr_ethernet_hdr_t*)pack->buf)->ether_dhost, header->ar_sha, ETHER_ADDR_LEN);
			sr_send_packet(sr, pack->buf, sizeof(sr_ethernet_hdr_t), pack->iface);
			request->packets = pack->next;
		}
		while(request != NULL);
		if (request == NULL)
		{
			fprintf(stderr, "No more requests.\n");
		}
		sr_arpreq_destroy(&(sr->cache),request);
	}
	else 
	{
		fprintf(stderr, "Call error.");
		return;
	}

}

uint8_t*  reply_icmp(uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t* ethHeader = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHeader = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint8_t  dest_mac[ETHER_ADDR_LEN];
  uint32_t dest_ip = ipHeader->ip_dst;
  
  /*Ethernet header address switch*/
  memcpy(dest_mac, ethHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ethHeader->ether_dhost, ethHeader->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethHeader->ether_shost, dest_mac, ETHER_ADDR_LEN);
  
  /*IP header address switch*/
  ipHeader->ip_dst = ipHeader->ip_src;
  ipHeader->ip_src = dest_ip;
  ipHeader->ip_sum = 0;
  ipHeader->ip_sum = cksum(ipHeader,20);
  
  /*ICMP header*/
  icmpHeader->icmp_type = 0x00;
  icmpHeader->icmp_code = 0x00;
  icmpHeader->icmp_sum = 0;
  icmpHeader->icmp_sum = cksum(icmpHeader, htons(ipHeader->ip_len) - 20);
  
  return packet;
}

uint8_t* t3_icmp(unsigned char *source_mac, unsigned char *dest_mac, uint32_t source_ip, uint32_t dest_ip, uint8_t type, uint8_t code, uint8_t* main)
{
  /*Header memory allocation*/
  int ethLen = sizeof(sr_ethernet_hdr_t);
  int ipLen = sizeof(sr_ip_hdr_t);
  int icmpLen = sizeof(sr_icmp_t3_hdr_t);
  uint8_t * packet = calloc(ethLen + ipLen + icmpLen, sizeof(uint8_t));
  sr_ethernet_hdr_t * ethHeader = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *) (packet + ethLen);
  sr_icmp_t3_hdr_t * icmpHead = (sr_icmp_t3_hdr_t *) (packet + ethLen + ipLen);
  
  /*Ethernet header*/
  memcpy(ethHeader->ether_dhost, dest_mac, ETHER_ADDR_LEN);
  memcpy(ethHeader->ether_shost, source_mac, ETHER_ADDR_LEN);
  ethHeader->ether_type = htons(ethertype_ip);
  
  /*IP header*/
  ipHeader->ip_v = 4;
  ipHeader->ip_hl = 5;
  ipHeader->ip_tos = 0;
  ipHeader->ip_len = htons(ipLen + icmpLen);
  ipHeader->ip_id = htons(0);
  ipHeader->ip_off = htons(0);
  ipHeader->ip_ttl = 64;
  ipHeader->ip_p = 1;
  ipHeader->ip_sum = 0;
  ipHeader->ip_src = source_ip; 
  ipHeader->ip_dst = dest_ip;
  ipHeader->ip_sum = cksum(ipHeader,20);

  /*ICMP header*/
  icmpHead->icmp_type = type;
  icmpHead->icmp_code = code;
  icmpHead->icmp_sum = 0;
  icmpHead->unused = 0;
  icmpHead->next_mtu = htons(1500);
  memcpy(icmpHead->data, main + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmpHead->icmp_sum = cksum(icmpHead, sizeof(sr_icmp_t3_hdr_t));
  
  return packet;
}

void handleIpPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if *interface)	{
  
  sr_ethernet_hdr_t* ethHeader = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHeader = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
  
  /*Check packet for mismatch*/
  uint16_t checksum = ipHeader->ip_sum;
  ipHeader->ip_sum = 0;
  if (checksum != cksum((uint8_t*)(packet+sizeof(sr_ethernet_hdr_t)),20))
    fprintf(stderr, "Checksum failure.\n");

  struct sr_if* ifList = sr->if_list;
  int routerMatch=0;
  while(ifList!=NULL)
  {
    if(ifList->ip == ipHeader->ip_dst)
      routerMatch= 1;
    ifList = ifList->next;
  }

  if(routerMatch)
  {
    if(ipHeader->ip_p == ip_protocol_icmp)
    {
		uint8_t * repICMP = reply_icmp(packet, len);
		print_hdrs(repICMP, 70);
		sr_send_packet(sr, repICMP, len, interface->name);
		return;
    }
    else
    {
		fprintf(stderr, "Port Unreachable\n");
		uint8_t * puICMP = t3_icmp(ethHeader->ether_shost, ethHeader->ether_dhost, ipHeader->ip_src, ipHeader->ip_dst, 3, 3, packet);
		print_hdrs(puICMP,70);
		sr_send_packet(sr,puICMP, sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), interface->name);
		return;
    }
  }
  else	{

    char *inter = NULL;
	unsigned int maskLength = 0;
	struct sr_rt* routingTable = sr->routing_table;
  
    while(routingTable != NULL)
    {
        if((routingTable->mask.s_addr & ipHeader->ip_dst) == (routingTable->mask.s_addr & routingTable->dest.s_addr))
        {
            long mask = routingTable->mask.s_addr;
            unsigned int j;
      
            for(j = 0; mask; j++)
                mask &= mask-1;
        
            if(j > maskLength)
            {
                maskLength = j;
                inter = routingTable->interface;
            }
        }
        routingTable = routingTable->next;
    }
  
    if(inter == NULL)
	{
		fprintf(stderr, "Net Unreachable\n");
		uint8_t * nuICMP = t3_icmp(ethHeader->ether_shost, ethHeader->ether_dhost, ipHeader->ip_src, ipHeader->ip_dst, 3, 0, packet);
		sr_send_packet(sr, nuICMP, sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), interface->name);
		return;
	}
    struct sr_if* inter_p = sr_get_interface(sr, inter);


    ipHeader->ip_ttl -= 1;
    ipHeader->ip_sum = cksum(ipHeader, 20);
    if(ipHeader->ip_ttl == 0)
    {
		fprintf(stderr, "Time to Live exceeded in Transit\n");
		uint8_t* teICMP = t3_icmp(ethHeader->ether_shost, ethHeader->ether_dhost, ipHeader->ip_src, ipHeader->ip_dst, 11, 0, packet);
		sr_send_packet(sr, teICMP, sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), interface->name);
		return;
    }
	struct sr_arpentry* arp_entry;
	uint32_t receiverifip = ntohl(interface->ip);
    arp_entry = sr_arpcache_lookup(&sr->cache, receiverifip);

    if(arp_entry != NULL)
    {
    memcpy(ethHeader->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(ethHeader->ether_shost, inter_p->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, inter_p->name);
    free(arp_entry);
    }
    else
    {
    struct sr_arpreq* a_req = sr_arpcache_queuereq(&(sr->cache), ipHeader->ip_dst, packet, len, inter_p->name);
    handle_arpreq(sr, a_req);
    }
  }
}

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
  print_hdrs(packet, len);
  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
  if(len < sizeof(sr_ethernet_hdr_t)) 
    return;


  struct sr_if* iface = sr_get_interface(sr, interface);
  if(ethertype(packet) == ethertype_arp) 
     handleArpPacket(sr, (sr_arp_hdr_t* )(packet+sizeof(sr_ethernet_hdr_t)), len-sizeof(sr_ethernet_hdr_t), iface);

  else if(ethertype(packet) == ethertype_ip)
  {
    int i=0;
    int bool=1;
    const uint8_t *add1=ether_hdr->ether_dhost; 
    const uint8_t *add2=iface->addr;
  while(i != ETHER_ADDR_LEN)
  {
    if (*add1 != *add2)
    {
      bool= 0;
      break;
    }
    ++add1;
    ++add2;
    i++;
  }
    if(bool)
      handleIpPacket(sr, packet, len, iface);

    else
      fprintf(stderr,"Not for this interface.\n");
  }
  else
    fprintf(stderr, "Dropped, wrong entertype.\n");

}/* end sr_ForwardPacket */
