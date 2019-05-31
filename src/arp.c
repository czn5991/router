#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");

	char *packet = (char *)malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);
	struct ether_header *ether_hdr = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	
	ether_hdr->ether_type = htons(ETH_P_ARP);
	memset(ether_hdr->ether_dhost, 0xff, ETH_ALEN);
	memcpy(ether_hdr->ether_shost, iface->mac, ETH_ALEN);
	arp_hdr->arp_hrd = htons(0x01);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REQUEST);
	arp_hdr->arp_spa = htonl(iface->ip);
	arp_hdr->arp_tpa = htonl(dst_ip);
	memset(arp_hdr->arp_tha, 0, ETH_ALEN);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);

	iface_send_packet(iface, packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");

	char *packet = (char *)malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);
	struct ether_header *ether_hdr = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct arp_hdr *)(packet + ETHER_HDR_SIZE);
	
	ether_hdr->ether_type = htons(ETH_P_ARP);
	memcpy(ether_hdr->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(ether_hdr->ether_shost, iface->mac, ETH_ALEN);
	arp_hdr->arp_hrd = htons(0x01);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REPLY);
	arp_hdr->arp_spa = htonl(iface->ip);
	arp_hdr->arp_tpa = htonl(req_hdr->arp_spa);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);
	memcpy(arp_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);

	iface_send_packet(iface,packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *arp_hdr = (struct arp_hdr *)(packet + ETHER_HDR_SIZE);
	if(ntohl(arp_hdr->arp_tpa) == iface->ip){
		switch (ntohs(arp_hdr->arp_op))
		{
		case ARPOP_REQUEST:
			arp_send_reply(iface, arp_hdr);
			arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);
			break;
		case ARPOP_REPLY:
			arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);
			break;
		default:
			break;
		}
	}
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
