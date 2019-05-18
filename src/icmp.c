#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "string.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr ip_hdr;
	int in_ip_hdr_size;
  
	struct icmphdr icmp_hdr;
	char* icmp_data;
	int icmp_data_size=0;
  
	char* out_pkt;

	//init icmp_data
	struct iphdr* in_ip_hdr = packet_to_ip_hdr(in_pkt);
	int offset = ETHER_HDR_SIZE;
	in_ip_hdr_size=in_ip_hdr->ihl*4;
	if(type==0&&code==0){
		offset +=in_ip_hdr_size + ICMP_HDR_SIZE;
		icmp_data_size=len-offset;
		icmp_data=(char*)malloc(icmp_data_size);
		strncpy(in_pkt+offset,icmp_data,icmp_data_size);
	}else{
		icmp_data_size=in_ip_hdr_size+8;
		icmp_data=(char*)malloc(icmp_data_size);
		memset(icmp_data,0,4*sizeof(char));
		strncpy(in_pkt+offset,icmp_data+4,icmp_data_size);
	}
  
	//init icmp hdr
	icmp_hdr.type=type;
	icmp_hdr.code=code;
	icmp_hdr.checksum=icmp_checksum(&icmp_hdr,ICMP_HDR_SIZE);
  
	//init ip hdr
	ip_init_hdr(&ip_hdr, in_ip_hdr->daddr, in_ip_hdr->saddr,
          icmp_data_size+ICMP_HDR_SIZE+IP_BASE_HDR_SIZE, in_ip_hdr->protocol);
  
	//init pkt to send
	out_pkt=(char*)malloc(IP_BASE_HDR_SIZE+ICMP_HDR_SIZE+icmp_data_size); 
	strncpy((char*)&ip_hdr,out_pkt,IP_BASE_HDR_SIZE);
	strncpy((char*)&icmp_hdr,out_pkt+IP_BASE_HDR_SIZE,ICMP_HDR_SIZE);
	strncpy(icmp_data,out_pkt+IP_BASE_HDR_SIZE+ICMP_HDR_SIZE,icmp_data_size);
	ip_send_packet(out_pkt,IP_BASE_HDR_SIZE+ICMP_HDR_SIZE+icmp_data_size);
    

	free(icmp_data);
	free(out_pkt);
  
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");
}
