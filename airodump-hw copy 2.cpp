#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <string>
#include <iomanip>
#include <iostream>

using namespace std;

typedef unsigned char u_char;

#define BEACON_TYPE 0x80 // IEEE 802.11 Beacon frame type

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
    char enc[8];           // Encryption type
    char essid[32];        // ESSID
    int power;             // Power level (dummy for now)
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
    // Clear screen for real-time update
    printf("\033[2J\033[H");

    // Print header
    printf("%-20s %-6s %-8s %-8s %-10s %-20s\n", "BSSID", "PWR", "Beacons", "#Data", "ENC", "ESSID");
    printf("--------------------------------------------------------------------------------\n");

    // Print each beacon's information
    for (const auto& entry : beacon_map) {
        const BeaconPacket& beacon = entry.second;
        printf("%-20s %-6d %-8d %-8d %-10s %-20s\n",
               mac_to_string(beacon.bssid).c_str(),
               beacon.power,  // Replace with actual signal power if available
               beacon.beacon_count,
               beacon.data_count,
               beacon.enc,
               beacon.essid);
    }
    printf("--------------------------------------------------------------------------------\n");
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
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        Radiotap_header *radiotap = (Radiotap_header *)packet;
        const u_char *frame = packet + radiotap->it_len;

        FrameControl *fc = (FrameControl *)frame;

        // Check if it is a beacon packet
        if (fc->type == 0 && fc->subtype == 8) {
            BeaconPacket beacon_packet;
            memset(&beacon_packet, 0, sizeof(beacon_packet));

            // Extract BSSID (MAC address at offset 16 in 802.11 frame)
            memcpy(&beacon_packet.bssid, frame + 16, sizeof(MacAddress));

            // Dummy data
            beacon_packet.beacon_count = 1;
            beacon_packet.data_count = 0;
            beacon_packet.power = -50;  // Example power value

            // Extract ESSID
            const u_char *tagged_params = frame + 36; // Start of tagged parameters
            uint8_t essid_len = tagged_params[1];
            memcpy(beacon_packet.essid, tagged_params + 2, essid_len);
            beacon_packet.essid[essid_len] = '\0';

            strcpy(beacon_packet.enc, "WPA2"); // Dummy encryption type

            // Update or insert into the map
            if (beacon_map.find(beacon_packet.bssid) != beacon_map.end()) {
                beacon_map[beacon_packet.bssid].beacon_count++;
            } else {
                beacon_map[beacon_packet.bssid] = beacon_packet;
            }

            // Display updated table
            display_table(beacon_map);
        }
    }

    pcap_close(pcap);
    return 0;
}
