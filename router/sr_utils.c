#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"

uint8_t* newERICMPPacket(uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  uint8_t  temp_mac[ETHER_ADDR_LEN];    /* source ethernet address */
  memcpy(temp_mac, e_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, temp_mac, ETHER_ADDR_LEN);
  uint32_t temp_ip;
  temp_ip = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = temp_ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr,20);
  uint8_t* icmp=packet+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t* type = icmp;
  *type = 0;
  uint8_t* code = type + sizeof(uint8_t);
  *code = 0;
  uint16_t* sum = (uint16_t*)(code + sizeof(uint8_t));
  *sum = 0;
  *sum = cksum(icmp, len- sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  return packet;
}

uint8_t* newHUICMPPacket(uint8_t* pkt, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos=0;     /* type of service */
  ip_hdr->ip_len=htons(56);      /* total length */
  ip_hdr->ip_id=htons(777);     /* identification */
  ip_hdr->ip_off=htons(IP_DF);      /* fragment offset field */
  ip_hdr->ip_ttl = 64;     /* time to live */
  ip_hdr->ip_p = 1;     /* protocol */
  ip_hdr->ip_sum =0;      /* checksum */
  ip_hdr->ip_src =sip; 
  ip_hdr->ip_dst =tip;  /* source and dest address */
  ip_hdr->ip_sum =cksum(ip_hdr,20);

  icmp_hdr->icmp_type=3;
  icmp_hdr->icmp_code=1;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = htons(1500);
  memcpy(icmp_hdr->data, pkt+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

uint8_t* newPUICMPPacket(uint8_t* pkt, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos=0;     /* type of service */
  ip_hdr->ip_len=htons(56);      /* total length */
  ip_hdr->ip_id=htons(777);     /* identification */
  ip_hdr->ip_off=htons(IP_DF);      /* fragment offset field */
  ip_hdr->ip_ttl = 64;     /* time to live */
  ip_hdr->ip_p = 1;     /* protocol */
  ip_hdr->ip_sum =0;      /* checksum */
  ip_hdr->ip_src =sip; 
  ip_hdr->ip_dst =tip;  /* source and dest address */
  ip_hdr->ip_sum =cksum(ip_hdr,20);

  icmp_hdr->icmp_type=3;
  icmp_hdr->icmp_code=3;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = htons(1500);
  memcpy(icmp_hdr->data, pkt+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

uint8_t* newNUICMPPacket(uint8_t* pkt, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos=0;     /* type of service */
  ip_hdr->ip_len=htons(56);      /* total length */
  ip_hdr->ip_id=htons(777);     /* identification */
  ip_hdr->ip_off=htons(IP_DF);      /* fragment offset field */
  ip_hdr->ip_ttl = 64;     /* time to live */
  ip_hdr->ip_p = 1;     /* protocol */
  ip_hdr->ip_sum =0;      /* checksum */
  ip_hdr->ip_src =sip; 
  ip_hdr->ip_dst =tip;  /* source and dest address */
  ip_hdr->ip_sum =cksum(ip_hdr,20);

  icmp_hdr->icmp_type=3;
  icmp_hdr->icmp_code=0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = htons(1500);
  memcpy(icmp_hdr->data, pkt+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

uint8_t* newTEICMPPacket(uint8_t* pkt, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(uint32_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*) (packet+ sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_ip);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos=0;     /* type of service */
  ip_hdr->ip_len=htons(56);      /* total length */
  ip_hdr->ip_id=htons(777);     /* identification */
  ip_hdr->ip_off=htons(IP_DF);      /* fragment offset field */
  ip_hdr->ip_ttl = 64;     /* time to live */
  ip_hdr->ip_p = 1;     /* protocol */
  ip_hdr->ip_sum =0;      /* checksum */
  ip_hdr->ip_src =sip; 
  ip_hdr->ip_dst =tip;  /* source and dest address */
  ip_hdr->ip_sum =cksum(ip_hdr,20);

  icmp_hdr->icmp_type=11;
  icmp_hdr->icmp_code=0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = htons(1500);
  memcpy(icmp_hdr->data, pkt+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  return packet;
}

struct sr_if* matchPrefix(struct sr_instance* sr, uint32_t ip)
{
    struct sr_rt* rt = sr->routing_table;
    unsigned int mask_length = 0;
    char *iface = NULL;
    while(rt != NULL)
    {
        if((rt->mask.s_addr & ip) == (rt->mask.s_addr & rt->dest.s_addr))
        {
            long mask = rt->mask.s_addr;
            unsigned int c;
            for(c = 0; mask; c++)
                mask &= mask-1;
            if(c > mask_length)
            {
                mask_length = c;
                iface = rt->interface;
            }
        }
        rt = rt->next;
    }
    if(iface == NULL)
		return NULL;
    else
      return sr_get_interface(sr, iface);
}

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

