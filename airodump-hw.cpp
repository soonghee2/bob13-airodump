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

    // Overload the < operator to use MacAddress as a key in std::map
    bool operator<(const MacAddress& other) const {
        return memcmp(this->addr, other.addr, sizeof(this->addr)) < 0;
    }
};

// Radiotap Header structure
typedef struct {
    uint8_t it_version;  /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;     /* entire length */
    uint32_t it_present; /* fields present */
} Radiotap_header;

// Frame Control structure
typedef struct {
    uint8_t version : 2;   // Protocol version
    uint8_t type : 2;      // Frame type
    uint8_t subtype : 4;   // Frame subtype
    uint8_t flags;         // Flags (to/from DS, etc.)
} FrameControl;

// Beacon Packet structure
typedef struct {
    MacAddress bssid;      // BSSID
    int beacon_count;      // Beacon count
    int data_count;        // Data count
    char enc[16];          // Encryption type
    char essid[32];        // ESSID
    int power;             // Power level
} BeaconPacket;

#pragma pack(pop)

// MAC address printing function
string mac_to_string(MacAddress mac) {
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
                 beacon.enc,
                 beacon.essid);
    }
    mvprintw(row, 0, "--------------------------------------------------------------------------------");
    refresh();
}

int find_signal_strength(const u_char* radiotap_data, uint32_t it_present, int header_len) {
    int offset = header_len;
    for (int i = 0; i < 32; ++i) {
        if (it_present & (1 << i)) {
            if (i == 5) { // Signal strength field
                return (int8_t)radiotap_data[offset];
            }
            offset += (i == 0 || i == 1 || i == 2 || i == 3 || i == 4 || i == 5 || i == 8) ? 1 :
                      (i == 6 || i == 9) ? 2 :
                      (i == 7 || i == 10) ? 4 : 0;
        }
    }
    return 0;
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
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            mvprintw(0, 0, "pcap_next_ex return %d(%s)", res, pcap_geterr(pcap));
            break;
        }

        Radiotap_header *radiotap = (Radiotap_header *)packet;
        const u_char *frame = packet + radiotap->it_len;

        FrameControl *fc = (FrameControl *)frame;

        if (fc->type == 0 && fc->subtype == 8) {
            BeaconPacket beacon_packet;
            memset(&beacon_packet, 0, sizeof(beacon_packet));

            memcpy(&beacon_packet.bssid, frame + 16, sizeof(MacAddress));
            beacon_packet.power = find_signal_strength(packet, radiotap->it_present, radiotap->it_len);

            const u_char *tagged_params = frame + 36;

            uint8_t essid_len = tagged_params[1];

            memcpy(beacon_packet.essid, tagged_params + 2, essid_len);
            beacon_packet.essid[essid_len] = '\0';

            strcpy(beacon_packet.enc, "OPEN");
            const u_char *rsn_info = (const u_char *)strstr((const char *)tagged_params, "\x30");
            if (rsn_info) {
                strcpy(beacon_packet.enc, "WPA2");
                if (strstr((const char *)rsn_info, "\x31")) {
                    strcpy(beacon_packet.enc, "WPA3");
                }
            }

            if (beacon_map.find(beacon_packet.bssid) != beacon_map.end()) {
                beacon_map[beacon_packet.bssid].beacon_count++;
            } else {
                beacon_packet.beacon_count = 1;
                beacon_map[beacon_packet.bssid] = beacon_packet;
            }
        } else if (fc->type == 2) {
            MacAddress bssid;
            memcpy(&bssid, frame + 16, sizeof(MacAddress));

            if (beacon_map.find(bssid) != beacon_map.end()) {
                beacon_map[bssid].data_count++;
            }
        }

        display_table(beacon_map);
    }

    endwin();
    pcap_close(pcap);
    return 0;
}
