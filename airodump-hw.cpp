#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <string>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <iomanip>

// 새로 만든 헤더 파일을 포함합니다.
#include "airodump-hw.h"

using namespace std;

typedef unsigned char u_char;

#define BEACON_TYPE 8 // IEEE 802.11 Beacon frame type
#define DATA_TYPE   0 // IEEE 802.11 Data frame type
#define FIXED_PARA 12

void usage() {
    printf("syntax: airodump-hw <interface>\n");
    printf("sample: airodump-hw wlan0\n");
}

string mac_to_string(const MacAddress& mac) {
    char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac.addr[0], mac.addr[1], mac.addr[2],
            mac.addr[3], mac.addr[4], mac.addr[5]);
    return string(mac_str);
}

void display_table(const map<MacAddress, BeaconPacket>& beacon_map) {
    system("clear");

    // 헤더 출력
    cout << left << setw(20) << "BSSID"
         << left << setw(10) << "PWR"
         << left << setw(10) << "Beacons"
         << left << setw(10) << "#Data"
         << left << setw(8)  << "ENC"
         << left << setw(32) << "ESSID"
         << endl;

    // 구분선 출력
    cout << string(60, '-') << endl;

    // 실제 정보 출력
    for (const auto& entry : beacon_map) {
        const BeaconPacket& beacon = entry.second;
        cout << left << setw(20) << mac_to_string(beacon.bssid)
             << left << setw(10) << beacon.power   // 현재 -1 고정 대신 beacon.power 사용 가능
             << left << setw(10) << beacon.beacon_count
             << left << setw(10) << beacon.data_count
             << left << setw(8)  << beacon.encryption
             << left << setw(32) << beacon.essid
             << endl;
    }
}

TaggedParameter parse_tagged_parameter(const u_char* data) {
    TaggedParameter param;
    param.tag_number = data[0];
    param.length = data[1];
    param.value = data + 2;
    return param;
}

bool parse_beacon_frame(const Frame80211* frame, const u_char* tagged_params, BeaconPacket& beacon_packet, size_t frame_length) {
    beacon_packet.bssid = frame->address3;
    beacon_packet.essid = "";
    beacon_packet.encryption = "OPEN"; // Default encryption

    // signal strength, data_count 등은 필요시 radiotap 정보에서 가져올 수 있음
    // 일단은 beacon_packet.power, beacon_packet.data_count를 0으로 초기화해둠
    beacon_packet.power = 0;
    beacon_packet.data_count = 0;

    const u_char* params_end = tagged_params + frame_length;
    //para

    while (tagged_params < params_end) {
        if (params_end - tagged_params < 2) break; // Prevent overflow

        TaggedParameter param = parse_tagged_parameter(tagged_params);

        if (param.tag_number==0 && param.length==0) break; // Prevent overflow

        if (param.tag_number == 0) { // SSID
            beacon_packet.essid = string((const char*)param.value, param.length);
        } 
        else if (param.tag_number == 48 || param.tag_number == 221) { 
            // RSN Information (WPA2/WPA3)
            if (param.length >= 2) {
                beacon_packet.encryption = "WPA2/3";
            }
        }
        tagged_params += 2 + param.length; // Move to next tag
    }
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    map<MacAddress, BeaconPacket> beacon_map;

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        const RadiotapHeader* radiotap = (const RadiotapHeader*)packet;
        // Radiotap 헤더 끝부터 802.11 Frame이 시작
        const Frame80211* frame = (const Frame80211*)(packet + radiotap->length);

        // Beacon Frame(Management Type=0, Subtype=8) 판별
        if (!(frame->fc.type == DATA_TYPE && frame->fc.subtype == BEACON_TYPE)) {
            continue;
        }

        BeaconPacket beacon_packet = {};
        // 주의: 실제로는 Radiotap 길이, Frame80211 길이를 정확히 계산해 SSID 등 태그 영역을 가져와야 합니다.
        // 여기서는 예시로 +12 오프셋을 줬지만, 무선 환경/디바이스별로 달라질 수 있습니다.
        parse_beacon_frame(frame, (const u_char*)frame + sizeof(Frame80211) + FIXED_PARA,
                           beacon_packet, header->caplen);

        auto it = beacon_map.find(beacon_packet.bssid);
        if (it != beacon_map.end()) {
            it->second.beacon_count++;
        } else {
            beacon_packet.beacon_count = 1;
            beacon_map[beacon_packet.bssid] = beacon_packet;
        }

        // 화면에 테이블 형태로 출력
        display_table(beacon_map);
        usleep(100000); // 0.1초 지연
    }

    pcap_close(pcap);
    return 0;
}
