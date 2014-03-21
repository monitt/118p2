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

/*Fill out ICMP packet*/
uint8_t* createTICMPPacket(uint8_t* packet, unsigned char *srcHa,
      uint32_t srcIP, unsigned char *destHa, uint32_t destIP)
{
  unsigned int length = sizeof(sr_ethernet_hdr_t) 
    + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(length);
  sr_ethernet_hdr_t* etHdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmpHdr = (sr_icmp_t3_hdr_t*) 
    (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(etHdr->ether_dhost, destHa, ETHER_ADDR_LEN);
  memcpy(etHdr->ether_shost, srcHa, ETHER_ADDR_LEN);
  etHdr->ether_type = htons(ethertype_ip);
  ipHdr->ip_v = 4;
  ipHdr->ip_p = 1;
  ipHdr->ip_sum =0;     
  ipHdr->ip_src =srcIP; 
  ipHdr->ip_dst =destIP;  
  ipHdr->ip_sum =cksum(ipHdr,20);
  ipHdr->ip_hl = 5;
  ipHdr->ip_tos=0;     
  ipHdr->ip_len=htons(56);      
  ipHdr->ip_id=htons(777);     
  ipHdr->ip_off=htons(IP_DF);      
  ipHdr->ip_ttl = 64;    
  icmpHdr->icmp_sum = 0;
  icmpHdr->unused = 0;
  icmpHdr->icmp_type=11;
  icmpHdr->icmp_code=0;
  icmpHdr->next_mtu = htons(1500);
  memcpy(icmpHdr->data, packet+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

/*Fill out ICMP packet*/
uint8_t* createPICMP(uint8_t* packet, unsigned char *srcHa, 
      uint32_t srcIP, unsigned char *destHa, uint32_t destIP)
{
  unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
        + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(length);
  sr_ethernet_hdr_t* etHdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmpHdr = (sr_icmp_t3_hdr_t*) 
          (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(etHdr->ether_dhost, destHa, ETHER_ADDR_LEN);
  memcpy(etHdr->ether_shost, srcHa, ETHER_ADDR_LEN);
  etHdr->ether_type = htons(ethertype_ip);
  ipHdr->ip_v = 4;
  ipHdr->ip_hl = 5;
  ipHdr->ip_tos=0;     /*service type*/
  ipHdr->ip_ttl = 64;     /*TTL*/
  ipHdr->ip_p = 1;     /*protocol*/
  ipHdr->ip_sum =0;      /*checksum*/
  ipHdr->ip_src =srcIP; 
  ipHdr->ip_dst =destIP;  /*src and dest*/
  ipHdr->ip_len=htons(56);      /*total length*/
  ipHdr->ip_id=htons(777);     /*ID*/
  ipHdr->ip_off=htons(IP_DF);      
  ipHdr->ip_sum =cksum(ipHdr,20);
  icmpHdr->icmp_type=3;
  icmpHdr->icmp_sum = 0;
  icmpHdr->unused = 0;
  icmpHdr->icmp_code=3;
  icmpHdr->next_mtu = htons(1500);
  memcpy(icmpHdr->data, packet+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

/*Fill out ICMP packet*/
uint8_t* createNICMP(uint8_t* packet, unsigned char *srcHa, 
      uint32_t srcIP, unsigned char *destHa, uint32_t destIP)
{
  unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
        + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(length);
  sr_ethernet_hdr_t* etHdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmpHdr = (sr_icmp_t3_hdr_t*) 
        (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(etHdr->ether_dhost, destHa, ETHER_ADDR_LEN);
  memcpy(etHdr->ether_shost, srcHa, ETHER_ADDR_LEN);
  etHdr->ether_type = htons(ethertype_ip);
  ipHdr->ip_v = 4;
  ipHdr->ip_hl = 5;
  ipHdr->ip_ttl = 64;     /*ttl*/
  ipHdr->ip_p = 1;    /*protocol*/
  ipHdr->ip_sum =0;    /*checksum*/
  ipHdr->ip_src =srcIP; 
  ipHdr->ip_dst =destIP; /*src and dest addr*/
  ipHdr->ip_sum =cksum(ipHdr,20);
  ipHdr->ip_tos=0;   /*service type*/
  ipHdr->ip_len=htons(56);     /*length*/
  ipHdr->ip_id=htons(777);    /*id*/
  ipHdr->ip_off=htons(IP_DF);    /*fragment offset*/
  icmpHdr->icmp_sum = 0;
  icmpHdr->unused = 0;
  icmpHdr->icmp_type=3;
  icmpHdr->icmp_code=0;
  icmpHdr->next_mtu = htons(1500);
  memcpy(icmpHdr->data, packet+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}


/*Fill out ICMP packet*/
uint8_t* createEICMP(uint8_t* packet, unsigned int length)
{
  sr_ethernet_hdr_t* etHdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  uint8_t  tempEther[ETHER_ADDR_LEN];    
  memcpy(tempEther, etHdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(etHdr->ether_dhost, etHdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(etHdr->ether_shost, tempEther, ETHER_ADDR_LEN);
  uint32_t tempIP;
  tempIP = ipHdr->ip_src;
  ipHdr->ip_src = ipHdr->ip_dst;
  ipHdr->ip_dst = tempIP;
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = cksum(ipHdr,20);
  uint8_t* icmp=packet+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t* type = icmp;
  *type = 0;
  uint8_t* code = type + sizeof(uint8_t);
  *code = 0;
  uint16_t* sum = (uint16_t*)(code + sizeof(uint8_t));
  *sum = 0;
  *sum = cksum(icmp, length- sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  return packet;
}

/*Match the prefix for routing table*/
struct sr_if* prefix(struct sr_instance* srInst, uint32_t ip)
{
  char *inter = NULL;
    unsigned int maskLength = 0;
  struct sr_rt* routingTable = srInst->routing_table;
  
    while(routingTable != NULL)
    {
        if((routingTable->mask.s_addr & ip) == 
      (routingTable->mask.s_addr & routingTable->dest.s_addr))
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
    return NULL;
    else
      return sr_get_interface(srInst, inter);
}

/**********************/
/*END HELPER FUNCTIONS*/
/**********************/


/*Handle IP Packet*/
void handleIpPacket(struct sr_instance* srInst, uint8_t* packet, 
                        unsigned int length, struct sr_if *inter)
{
  sr_ethernet_hdr_t* etHdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
  uint16_t csum = ipHdr->ip_sum;
  ipHdr->ip_sum = 0;
  
  if (csum != cksum((uint8_t*)(packet+sizeof(sr_ethernet_hdr_t)),20))
  {
    fprintf(stderr, "Checksum mismatch\n");
  }

  if(isRouterIp(srInst,ipHdr->ip_dst))
  {
    if(ipHdr->ip_p == ip_protocol_icmp)
    {
    uint8_t * eICMP = createEICMP(packet,length);
    sr_send_packet(srInst,eICMP,length,inter->name);
    return;
    }
    else /*IP pack, send ICMP back*/
    {
    uint8_t * pICMP = createPICMP(packet,etHdr->ether_dhost,inter->ip,etHdr->ether_shost,ipHdr->ip_src);
    if(sr_send_packet(srInst,pICMP,sizeof(sr_icmp_t3_hdr_t)
          +sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t),inter->name)==-1)
      fprintf(stderr,"Error didnt send pICMP\n");
    return;
    }
  }
  else
  {
  /*send NICMP packet*/
  struct sr_if* interP = prefix(srInst,ipHdr->ip_dst);
  
  if(interP==NULL)
  {
    uint8_t * nICMP = createNICMP(packet,etHdr->ether_dhost,inter->ip,
                    etHdr->ether_shost,ipHdr->ip_src);
    if(sr_send_packet(srInst,nICMP,sizeof(sr_icmp_t3_hdr_t)
            +sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t),inter->name)==-1)
      fprintf(stderr,"Error didnt send nICMP\n");
    return;
  }

    ipHdr->ip_ttl--;
    ipHdr->ip_sum = 0;
  ipHdr->ip_sum = cksum(ipHdr,20);
  
    if(ipHdr->ip_ttl == 0)
    {
      /*exceeded time*/
      fprintf(stderr, "ICMP time exceeded.\n");
    uint8_t* tICMP = createTICMPPacket(packet,inter->addr,inter->ip,
                    etHdr->ether_shost,ipHdr->ip_src);
      if(sr_send_packet(srInst,tICMP,sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)
                +sizeof(sr_ethernet_hdr_t),inter->name)==-1)
      fprintf(stderr,"Error didnt send tICMP\n");
    return;
    }

    /*routing*/
    struct sr_arpentry* arpEnt;
    uint32_t ipRec = ntohl(inter->ip);
    arpEnt = sr_arpcache_lookup(&srInst->cache, ipRec);

    if(arpEnt != NULL)
    { 
  /*copy over*/
      memcpy(etHdr->ether_dhost, arpEnt->mac, ETHER_ADDR_LEN);
    memcpy(etHdr->ether_shost, interP->addr, ETHER_ADDR_LEN);
      sr_send_packet(srInst, packet, length, interP->name);
      free(arpEnt);     /*free the space*/
    }
    else
    {
    struct sr_arpreq* aRequest = sr_arpcache_queuereq(&(srInst->cache), 
                ipHdr->ip_dst, packet, length, interP->name);
    handle_arpreq(srInst, aRequest);
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