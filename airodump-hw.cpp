#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>

typedef unsigned char u_char;

#define BEACON_TYPE 0x80 // IEEE 802.11 Beacon frame type


void usage() {
	printf("syntax: airodump-hw <interface>\n");
	printf("sample: airodump-hw wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

#pragma pack(push, 1) // 1바이트 정렬 강제
// MAC 주소 구조체
typedef struct {
    uint8_t addr[6];
} MacAddress;

struct ieee80211_radiotap_header {
    uint8_t it_version;  /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;     /* entire length */
    uint32_t it_present; /* fields present */
} Radiotap_header;


// 비콘 패킷 구조체
typedef struct {
    MacAddress bssid;
    uint16_t beacon_count;
    uint16_t data_count;
    char enc[10];
    char essid[33]; // ESSID 최대 길이는 32바이트 + NULL 문자
} BeaconPacket;
#pragma pack(pop)

// MAC 주소 출력 함수
void print_mac(MacAddress mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac.addr[0], mac.addr[1], mac.addr[2], 
           mac.addr[3], mac.addr[4], mac.addr[5]);
}

// 비콘 패킷 출력 함수
void print_beacon_info(const BeaconPacket *packet) {
    printf("BSSID: ");
    print_mac(packet->bssid);
    printf(", Beacons: %d, #Data: %d, ENC: %s, ESSID: %s\n",
           packet->beacon_count, packet->data_count, packet->enc, packet->essid);
}

int main(int argc, char* argv[]) {
    if (argc != 2) { usage(); return -1;}

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

		// Radiotap Header 추출
        const struct ieee80211_radiotap_header* radiotap_hdr = (const struct ieee80211_radiotap_header*)packet;
        uint16_t radiotap_len = radiotap_hdr->it_len;
        

        // IEEE 802.11 무선 LAN 헤더
        const uint8_t* frame = packet + radiotap_len;
        const uint8_t frame_type = frame[0];
        if (frame_type != BEACON_TYPE) {
            continue; // 비콘 패킷이 아니면 무시
        }

        BeaconPacket beacon_packet;

        // BSSID 추출 (MAC 주소는 10~15 바이트 위치)
        memcpy(beacon_packet.bssid.addr, &frame[10], 6);

        // 비콘 카운트, 데이터 카운트 (데이터는 가상으로 설정)
        beacon_packet.beacon_count = 0; // 실제 데이터에서 계산하려면 추가 작업 필요
        beacon_packet.data_count = 0;   // 캡처 데이터 활용

        // 암호화 방식 추출 (간단히 OPEN으로 설정)
        strcpy(beacon_packet.enc, "OPEN");

        // ESSID 추출 (SSID는 36 바이트 이후 시작)
        uint8_t ssid_length = frame[37];
        if (ssid_length > 32) ssid_length = 32; // 최대 ESSID 길이 제한
        memcpy(beacon_packet.essid, &frame[38], ssid_length);
        beacon_packet.essid[ssid_length] = '\0'; // NULL 종료

        // 비콘 정보 출력
        print_beacon_info(&beacon_packet);
	}

	pcap_close(pcap);
}