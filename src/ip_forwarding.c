#include "ip.h"
#include "icmp.h"
#include "rtable.h"
#include "arp.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>

// forward the IP packet from the interface specified by longest_prefix_match, 
// when forwarding the packet, you should check the TTL, update the checksum,
// determine the next hop to forward the packet, then send the packet by 
// iface_send_packet_by_arp
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr* ip_hdr = packet_to_ip_hdr(packet);

	//ttl=0,send icmp
	if (--ip_hdr->ttl <= 0){
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}
	ip_hdr->checksum = ip_checksum(ip_hdr);

	rt_entry_t* entry = longest_prefix_match(ip_dst);
	//no target entry in route table,send icmp
	if (entry == NULL){
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return;
	}

	u32 next_hop = entry->gw;
	if (!next_hop) next_hop = ip_dst;

	iface_send_packet_by_arp(entry->iface, ip_dst, packet, len);
	
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		//fprintf(stderr, "TODO: reply to the sender if it is ping packet.\n");
		icmp_send_packet(packet, len, 0, 0);
		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
