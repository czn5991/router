#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "string.h"
#include "packet.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{

	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	struct ether_header* ether_hdr;

	struct iphdr* ip_hdr;
	int in_ip_hdr_size;

	struct icmphdr* icmp_hdr;
	char* icmp_data;
	int icmp_data_size = 0;

	char* out_pkt;

	//malloc out_pkt and init icmp_data
	struct iphdr* in_ip_hdr = packet_to_ip_hdr(in_pkt);
	in_ip_hdr_size = in_ip_hdr->ihl * 4;
	if (type == ICMP_ECHOREPLY){
		struct icmphdr* in_icmp_hdr = (struct icmphdr*)(in_pkt + ETHER_HDR_SIZE + in_ip_hdr_size);
		if (in_icmp_hdr->type == ICMP_DEST_UNREACH || in_icmp_hdr->type == ICMP_TIME_EXCEEDED)
			return;
		int in_icmp_data_offset = ETHER_HDR_SIZE + in_ip_hdr_size + ICMP_HDR_SIZE;
		icmp_data_size = len - in_icmp_data_offset;
		out_pkt = (char*)calloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + icmp_data_size,sizeof(char));
		icmp_data = out_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE;
		memcpy(icmp_data, in_pkt + in_icmp_data_offset, icmp_data_size);
	}
	else{
		icmp_data_size = in_ip_hdr_size + 8;
		out_pkt = (char*)calloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + icmp_data_size, sizeof(char));
		icmp_data = out_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE;
		memset(icmp_data, 0, 4 * sizeof(char));
		memcpy(icmp_data, in_pkt + ETHER_HDR_SIZE, in_ip_hdr_size + 8);
	}

	ether_hdr = (struct ether_header*)out_pkt;
	ip_hdr = packet_to_ip_hdr(out_pkt);
	icmp_hdr = (struct icmphdr*)(out_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);

	//init icmp hdr
	memcpy(icmp_hdr, in_pkt + ETHER_HDR_SIZE + in_ip_hdr_size, ICMP_HDR_SIZE);
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = icmp_checksum(icmp_hdr, ICMP_HDR_SIZE + icmp_data_size);


	//init ip hdr
	ip_init_hdr(ip_hdr, ntohl(in_ip_hdr->daddr), ntohl(in_ip_hdr->saddr),
		icmp_data_size + ICMP_HDR_SIZE + IP_BASE_HDR_SIZE, in_ip_hdr->protocol);
	

	//init ether hdr
	//it's ok if don't set the ether addr cause it will be set when send by arp
	struct ether_header* in_ether_hdr = (struct ether_header*) in_pkt;
	memcpy(ether_hdr->ether_dhost, in_ether_hdr->ether_shost, ETH_ALEN);
	memcpy(ether_hdr->ether_shost, in_ether_hdr->ether_dhost, ETH_ALEN);
	ether_hdr->ether_type = htons(ETH_P_IP);

	ip_send_packet(out_pkt, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + icmp_data_size); 


}