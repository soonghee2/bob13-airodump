#pragma once

#include <cstdint>
#include <cstring>
#include <string>

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
    const uint8_t* value;
};

// Beacon Packet structure
struct BeaconPacket {
    MacAddress bssid;      // BSSID
    int beacon_count;      // Beacon count
    int data_count;        // Data count
    std::string encryption;     // Encryption type
    std::string essid;          // ESSID
    int power;             // Signal strength
};

#pragma pack(pop)
