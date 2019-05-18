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
	if (--ip_hdr->ttl <= 0)
		icmp_send_packet(packet,len,11,0);
	ip_checksum(ip_hdr);

	rt_entry_t* entry=longest_prefix_match(ip_dst);
	if (entry!=NULL)
		iface_send_packet_by_arp(entry->iface,ip_dst, packet, len);
	//no target entry in route table,send icmp
	else
		icmp_send_packet(packet, len, 3, 0);
	
	fprintf(stderr, "TODO: forward ip packet.\n");
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
		icmp_send_packet(packet, len, 0, 0);
		fprintf(stderr, "TODO: reply to the sender if it is ping packet.\n");
		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
