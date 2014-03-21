#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
 struct sr_arpreq *r = sr->cache.requests;  /*taking the cache requests.*/
 while(r!=NULL)  /*loops the linked list till all reqs are complete*/
 {
    /*handle*/
    time_t now;
    time(&now);
    if(difftime(now, r->sent) > 1) /*if the time difference obtained is greater than 1 sec*/
    {
      if(r->times_sent >= 5)  /*and more than req is sent more than 5 times*/
      {
        struct sr_packet* currpkt = r->packets;
        while(currpkt!=NULL)
        {
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) currpkt->buf;
            sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*) (currpkt->buf+sizeof(sr_ethernet_hdr_t));

            uint8_t *icmp_message = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), sizeof(uint8_t));
            sr_ethernet_hdr_t * eth_head_icmp = (sr_ethernet_hdr_t*) icmp_message;
            sr_ip_hdr_t * ip_head_icmp = (sr_ip_hdr_t*)(icmp_message + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t * icmp_head_icmp = (sr_icmp_t3_hdr_t*)(icmp_message + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            eth_head_icmp->ether_type = ntohs(ethertype_ip);
            memcpy(eth_head_icmp->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_head_icmp->ether_shost, sr_get_interface(sr,currpkt->iface)->addr, ETHER_ADDR_LEN);
            
            ip_head_icmp->ip_hl = 5; 
            ip_head_icmp->ip_v = 4;
            ip_head_icmp->ip_tos = htonl(0);
            ip_head_icmp->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            ip_head_icmp->ip_id = 0;
            ip_head_icmp->ip_off = 0;
            ip_head_icmp->ip_ttl = 255; 
            ip_head_icmp->ip_p = 1;
            ip_head_icmp->ip_src = sr_get_interface(sr, currpkt->iface)->ip; 
            ip_head_icmp->ip_dst = iphdr->ip_src;
            ip_head_icmp->ip_sum = cksum(ip_head_icmp, 20);  
            icmp_head_icmp->icmp_type = 3;
            icmp_head_icmp->icmp_code = 1;
       
            memcpy(icmp_head_icmp->data, iphdr, ICMP_DATA_SIZE);
            icmp_head_icmp->icmp_sum = cksum(icmp_head_icmp, sizeof(sr_icmp_t3_hdr_t));

            sr_send_packet(sr, icmp_message, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), currpkt->iface);
            currpkt = currpkt->next;
        }
        sr_arpreq_destroy(&(sr->cache), r);
      }
       
      else
      {
        struct sr_if * iface_pt = sr->if_list;
        uint8_t * arp_request = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),sizeof(uint8_t));
        sr_ethernet_hdr_t * eth_head_request = (sr_ethernet_hdr_t*) arp_request;
        sr_arp_hdr_t * arp_head_request = (sr_arp_hdr_t *) (arp_request + sizeof(sr_ethernet_hdr_t)); 

        eth_head_request->ether_type = ntohs(ethertype_arp); 
        unsigned long floodAddr = 0xFFFFFFFFFFFF; 
        memcpy(eth_head_request->ether_dhost, &floodAddr, ETHER_ADDR_LEN);

        arp_head_request->ar_hrd = ntohs(arp_hrd_ethernet);
        arp_head_request->ar_pro = ntohs(ethertype_ip);
        arp_head_request->ar_hln = ETHER_ADDR_LEN;
        arp_head_request->ar_pln = 4;
        arp_head_request->ar_op = ntohs(arp_op_request);
        arp_head_request->ar_tip = r->ip;
        memcpy(arp_head_request->ar_tha, &floodAddr, ETHER_ADDR_LEN);

        while(iface_pt != 0)
        {
        memcpy(eth_head_request->ether_shost, iface_pt->addr, ETHER_ADDR_LEN);
        memcpy(arp_head_request->ar_sha, eth_head_request->ether_shost, ETHER_ADDR_LEN);
        arp_head_request->ar_sip = iface_pt->ip;
        sr_send_packet(sr, arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface_pt->name);
        iface_pt = iface_pt->next;
        }
        r->sent = now;
        r->times_sent=r->times_sent+1;

      }

   }
    
    r=r->next;        /*set to the next req*/
 }

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

