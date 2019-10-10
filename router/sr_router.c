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

uint8_t* build_ether_packet(unsigned int len, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t type) {
    uint8_t* packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + len);
    assert(packet);
    memset(packet, 0, sizeof(sr_ethernet_hdr_t) + len);
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
    ehdr->ether_type = htons(type);
    memcpy(ehdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
    return packet;
}

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
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "packet size is less than the minimum size");
        return;
    }
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
    if (ntohs(ehdr->ether_type) == ethertype_arp) {
        if (len - sizeof(sr_ethernet_hdr_t) < 0) {
            fprintf(stderr, "incomplete ARP packet\n");
            return;
        }
        printf("*** -> Received ARP packet of length %lu from %s\n",len - sizeof(sr_ethernet_hdr_t), interface);
        sr_arp_hdr_t* ahdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        if (ntohs(ahdr->ar_op) == arp_op_request) {
            struct sr_if* itf = sr_get_interface(sr, interface);
            uint8_t *response = build_ether_packet(sizeof(sr_arp_hdr_t),  ehdr->ether_shost, itf->addr, ethertype_arp);
            assert(response);
            memcpy(response + sizeof(sr_ethernet_hdr_t), ahdr, sizeof(sr_arp_hdr_t));
            sr_arp_hdr_t* response_ahdr = (sr_arp_hdr_t*) (response + sizeof(sr_ethernet_hdr_t));
                response_ahdr->ar_op = htons(arp_op_reply);
            memcpy(response_ahdr->ar_sha, ahdr->ar_tha, ETHER_ADDR_LEN);
            response_ahdr->ar_sip = ahdr->ar_tip;
            memcpy(response_ahdr->ar_tha, ahdr->ar_sha, ETHER_ADDR_LEN);
            response_ahdr->ar_tip = ahdr->ar_sip;
            sr_send_packet(sr, (uint8_t *)response, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), interface);
            free(response);
        }
        else if (ntohs(ahdr->ar_op) == arp_op_reply) {
            printf("reply for me\n");
        }
        else {
            fprintf(stderr, "unknown ARP packet type\n");
        }
    }
    else if (ntohs(ehdr->ether_type) == ethertype_ip) {
        if (len - sizeof(sr_ip_hdr_t) < 0) {
            fprintf(stderr, "incomplete IP packet\n");
            return;
        }
        sr_ip_hdr_t* ihdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
        printf("*** -> Received IP packet of length %d \n", len - sizeof(sr_ethernet_hdr_t));
        
    }
    else {
        fprintf(stderr, "unkonwn packet type\n");
    }
    return;
    /* fill in code here */
}/* end sr_ForwardPacket */

