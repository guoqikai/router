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

void write_ethernet_header(uint8_t* packet, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t type) {
    assert(packet);
    assert(ether_dhost);
    assert(ether_shost);
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
    ehdr->ether_type = htons(type);
    memcpy(ehdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
}

void write_arp_header(uint8_t* packet, unsigned short op, unsigned char* sha, uint32_t sip, unsigned char* tha, uint32_t tip) {
    assert(packet);
    assert(sha);
    sr_arp_hdr_t *ahdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    ahdr->ar_hrd = htons(arp_hrd_ethernet);
    ahdr->ar_pro = htons(0x800);
    ahdr->ar_hln = ETHER_ADDR_LEN;
    ahdr->ar_pln = sizeof(uint32_t);
    ahdr->ar_op = htons(op);
    memcpy(ahdr->ar_sha, sha, ETHER_ADDR_LEN);
    ahdr->ar_sip = sip;
    if (op == arp_op_request || !tha) {
        memset(ahdr->ar_tha, 0, ETHER_ADDR_LEN);
    }
    else {
        memcpy(ahdr->ar_tha, tha, ETHER_ADDR_LEN);
    }
    ahdr->ar_tip = tip;
}


void send_ip_packet(struct sr_instance* sr, uint8_t* buffer, unsigned int len, char* s_interface, char* t_interface) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "unable to send ip packet: incompelet IP packet\n");
        return;
    }
    struct sr_if* itf = sr_get_interface(sr, t_interface);
    uint32_t ip = itf->ip;
    struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), ip);
    if (entry) {
        write_ethernet_header(buffer, entry->mac, itf->addr, ethertype_ip);
        sr_send_packet(sr, buffer, len, itf->name);
        free(entry);
    }
    else {
        uint8_t empty[6] = {0};
        write_ethernet_header(buffer, empty, itf->addr, ethertype_ip);
        struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip, buffer, len, s_interface);
        handle_arpreq(sr, req);
    }
}

void send_ICMP_packet(struct sr_instance* sr, unsigned int type, unsigned int code, char* interface) {
    struct sr_if* itf = sr_get_interface(sr, interface);
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
            uint8_t *response = (uint8_t*)malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
            assert(response);
            write_ethernet_header(response, ehdr->ether_shost, itf->addr, ethertype_arp);
            write_arp_header(response, arp_op_reply, itf->addr, itf->ip, ahdr->ar_sha, ahdr->ar_sip);
            sr_send_packet(sr, response, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), interface);
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
        uint8_t* ip_packet = (uint8_t*)malloc(len);
        assert(ip_packet);
        memcpy(ip_packet, packet, len);
        sr_ip_hdr_t* ihdr = (sr_ip_hdr_t*) (ip_packet + sizeof(sr_ethernet_hdr_t));
        int sum = ihdr->ip_sum;
        ihdr->ip_sum = 0;
        printf("*** -> Received IP packet of length %lu \n", len - sizeof(sr_ethernet_hdr_t));
        if (cksum(ihdr, sizeof(sr_ip_hdr_t)) - sum) {
            fprintf(stderr, "IP packet has invalid check sum\n");
            return;
        }
        struct sr_if* itf = sr->if_list;
        while (itf){
            if (itf->ip == ihdr->ip_dst) {
                free(ip_packet);
                return;
            }
            itf = itf->next;
        }
        ihdr->ip_ttl--;
        char* interface_name = get_longest_prefix_matched_interface(sr, ihdr->ip_dst);
        if (!ihdr->ip_ttl) {
            printf("timeout");
        }
        else if (interface_name) {
            sum = cksum(ihdr, sizeof(sr_ip_hdr_t));
            ihdr->ip_sum = sum;
            send_ip_packet(sr, ip_packet, len, interface, interface_name);
        }
        else {
            printf("wrong ip\n");
        }
        free(ip_packet);
    }
    else {
        fprintf(stderr, "unkonwn packet type\n");
    }
    return;
    /* fill in code here */
}/* end sr_ForwardPacket */

