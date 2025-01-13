#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>

typedef unsigned char u_char;


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void printHex(const void *ptr, size_t size) {
    const uint8_t *bytePtr = (const uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", bytePtr[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void printMAC(const u_char *src_mac, const u_char *dst_mac) {
	printf("\n--Ethernet Header\n");
    	printf("Src MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           src_mac[0], src_mac[1], src_mac[2],
           src_mac[3], src_mac[4], src_mac[5]);
    	printf("Dst MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           dst_mac[0], dst_mac[1], dst_mac[2],
           dst_mac[3], dst_mac[4], dst_mac[5]);
}

void printIPs(const struct in_addr *src_ip, const struct in_addr *dst_ip) {
    	printf("\n--IP Header\n");
    	printf("Src IP Address: %s\n", inet_ntoa(*src_ip));
    	printf("Dst IP Address: %s\n", inet_ntoa(*dst_ip));
}

void printTCPPorts(uint16_t src_port, uint16_t dst_port) {
	printf("\n--TCP Header\n");
    	printf("Src Port number: %u\n", ntohs(src_port));
    	printf("Dst Port number: %u\n", ntohs(dst_port));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
		
		const  uint8_t* payload = (uint8_t*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)+ sizeof(struct libnet_tcp_hdr));
		size_t payload_size = header->caplen - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
		
		if (ipv4_hdr->ip_p == 0x06){

			printf("\n-------new TCP Packet--------\n");
		
		printMAC(ethernet_hdr->ether_shost, ethernet_hdr -> ether_dhost);  // 소스 MAC 주소
       		printIPs(&ipv4_hdr->ip_src, &ipv4_hdr ->ip_dst);  // 소스 IP 주소
		printTCPPorts(tcp_hdr->th_sport, tcp_hdr->th_dport);  // 소스 및 목적지 포트
		
		printf("Payload (up to 20 bytes): \n");
            	printHex(payload, payload_size < 20 ? payload_size : 20);

	
		}
	}

	pcap_close(pcap);
}