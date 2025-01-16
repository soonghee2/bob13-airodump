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
#include <ncurses.h>

using namespace std;

typedef unsigned char u_char;

#define BEACON_TYPE 0x80 // IEEE 802.11 Beacon frame type
#define DATA_TYPE 0x20   // IEEE 802.11 Data frame type

void usage() {
    printf("syntax: airodump-hw <interface>\n");
    printf("sample: airodump-hw wlan0\n");
}

#pragma pack(push, 1) // 1-byte alignment

// MAC Address structure
struct MacAddress {
    uint8_t addr[6];

    bool operator<(const MacAddress& other) const {
        return memcmp(this->addr, other.addr, sizeof(this->addr)) < 0;
    }
};

// Radiotap Header structure
struct RadiotapHeader {
    uint8_t version;    // Always 0
    uint8_t pad;
    uint16_t length;    // Total length of the radiotap header
    uint32_t present;   // Bitmask indicating available fields
};

// Frame Control structure
struct FrameControl {
    uint8_t version : 2;   // Protocol version
    uint8_t type : 2;      // Frame type
    uint8_t subtype : 4;   // Frame subtype
    uint8_t flags;         // Flags (to/from DS, etc.)
};

// 802.11 Frame structure
struct Frame80211 {
    FrameControl fc;
    uint16_t duration;
    MacAddress address1;
    MacAddress address2;
    MacAddress address3;
    uint16_t sequence_control;
    // Followed by frame body (variable length)
};

// Tagged Parameter structure
struct TaggedParameter {
    uint8_t tag_number;
    uint8_t length;
    const u_char* value;
};

// Beacon Packet structure
struct BeaconPacket {
    MacAddress bssid;      // BSSID
    int beacon_count;      // Beacon count
    int data_count;        // Data count
    string encryption;     // Encryption type
    string essid;          // ESSID
    int power;             // Signal strength
};

#pragma pack(pop)

string mac_to_string(const MacAddress& mac) {
    char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac.addr[0], mac.addr[1], mac.addr[2],
            mac.addr[3], mac.addr[4], mac.addr[5]);
    return string(mac_str);
}

void display_table(const map<MacAddress, BeaconPacket>& beacon_map) {
    clear();
    mvprintw(0, 0, "%-20s %-6s %-8s %-8s %-10s %-20s", "BSSID", "PWR", "Beacons", "#Data", "ENC", "ESSID");
    mvprintw(1, 0, "--------------------------------------------------------------------------------");

    int row = 2;
    for (const auto& entry : beacon_map) {
        const BeaconPacket& beacon = entry.second;
        mvprintw(row++, 0, "%-20s %-6d %-8d %-8d %-10s %-20s",
                 mac_to_string(beacon.bssid).c_str(),
                 beacon.power,
                 beacon.beacon_count,
                 beacon.data_count,
                 beacon.encryption.c_str(),
                 beacon.essid.c_str());
    }
    mvprintw(row, 0, "--------------------------------------------------------------------------------");
    refresh();
}

TaggedParameter parse_tagged_parameter(const u_char* data) {
    TaggedParameter param;
    param.tag_number = data[0];
    param.length = data[1];
    param.value = data + 2;
    return param;
}

void parse_beacon_frame(const Frame80211* frame, const u_char* tagged_params, BeaconPacket& beacon_packet, size_t frame_length) {
    beacon_packet.bssid = frame->address3;
    beacon_packet.essid = "";
    beacon_packet.encryption = "OPEN";

    const u_char* params_end = tagged_params + frame_length;
    while (tagged_params < params_end) {
        TaggedParameter param = parse_tagged_parameter(tagged_params);
        if (param.tag_number == 0) {
            beacon_packet.essid = string((const char*)param.value, param.length);
        } else if (param.tag_number == 48) {
            beacon_packet.encryption = "WPA2";
        } else if (param.tag_number == 221) {
            beacon_packet.encryption = "WPA3";
        }
        tagged_params += 2 + param.length;
    }
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

    initscr();
    cbreak();
    noecho();

    map<MacAddress, BeaconPacket> beacon_map;

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        const RadiotapHeader* radiotap = (const RadiotapHeader*)packet;
        const Frame80211* frame = (const Frame80211*)(packet + radiotap->length);

        if (frame->fc.type == 0 && frame->fc.subtype == 8) {
            BeaconPacket beacon_packet = {};
            parse_beacon_frame(frame, (const u_char*)frame + sizeof(Frame80211)+12, beacon_packet, header->caplen);

            auto it = beacon_map.find(beacon_packet.bssid);
            if (it != beacon_map.end()) {
                it->second.beacon_count++;
            } else {
                beacon_packet.beacon_count = 1;
                beacon_map[beacon_packet.bssid] = beacon_packet;
            }
        }

        display_table(beacon_map);
    }

    endwin();
    pcap_close(pcap);
    return 0;
}
