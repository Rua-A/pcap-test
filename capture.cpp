#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdlib.h>

int packet_capture(char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    while (true) 
    {
            struct pcap_pkthdr* header;
            const u_char* packet;

            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) 
            {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            printf("\n----------------------------------------------\n");
            printf("%u bytes captured\n", header->caplen);       
            
            if(packet[0xc] == 0x08|packet[0xd]==0x00)
            {
            	//total fix
            	//total, version
            	//uint32_t ip_version = packet[0xe]&0xf0 ;
            	//uint32_t ip_head_len = packet[0xe]&0x0f;
            	//printf("%x:%x\n",ip_version,ip_head_len);
            	//uint32_t total_len = packet[0x10]&0xff00|packet[0x11]&0x00ff;
            	uint32_t TCP = packet[0x17];
            	printf("Protocol : IPv4\n");
            	if(TCP == 0x06){
            	printf("Protocol : TCP\n");
            	//MAC
            printf("Src_MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0x6],packet[0x7],packet[0x8],packet[0x9],packet[0xa],packet[0xb]);
            printf("Dst_Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0x0],packet[0x1],packet[0x2],packet[0x3],packet[0x4],packet[0x5]);
            	
            	//IP/TCP
            	printf("Src IP : %d.%d.%d.%d\n",packet[0x1a],packet[0x1b],packet[0x1c],packet[0x1d]);
        	printf("Dst IP : %d.%d.%d.%d\n",packet[0x1e],packet[0x1f],packet[0x20],packet[0x21]);
        	
        	//PORT
        	uint32_t Src_port_hex[] = {packet[0x22], packet[0x23]};
        	uint32_t* Src_port = reinterpret_cast<uint32_t*>(Src_port_hex);
        	uint32_t Source_port = ntohs(*Src_port);
        	uint32_t Dst_port_hex[] = { packet[0x24], packet[0x25]};
        	uint32_t* Dest_port = reinterpret_cast<uint32_t*>(Dst_port_hex);
		uint32_t Destination_port = ntohs(*Dest_port);
        	printf("Src PROT : %d\n",Source_port);
        	printf("Dst PROT : %d\n",Destination_port);
        	
        	//payload
        	uint32_t payload_c = 0x00;
        	uint32_t payload[1];
		payload[0] = packet[0x10]&0xff;
		payload[1] = packet[0x11]&0xff;
		uint32_t payload_len = payload[0]<<8|payload[1]<<0;
		
		payload_len = payload_len - 0x28;
		printf("%04x\n",payload_len);
 		
 		while(payload_c<payload_len)
       		{		
            		printf("%02x",packet[0x36+payload_c]); //0x36
            		payload_c+=0x01;
        	}
        	payload_c=0x00;
            }    
	}
	}
	pcap_close(handle);
	return 0;
}


