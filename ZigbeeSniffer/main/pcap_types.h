#ifndef PCAP_TYPES
#define PCAP_TYPES

#include <string.h>

#define MAX_SOURCE_FRAME_LEN          256 // 170 enough if max pirs-len is 73

// Main PCAP-header params
#define FILE_HEADER_MAGIC_NUMBER      0xA1B2C3D4
#define FILE_HEADER_VERSION_MAJOR     0x0002
#define FILE_HEADER_VERSION_MINOR     0x0004
#define FILE_HEADER_RESERVED_1        0x00000000
#define FILE_HEADER_RESERVED_2        0x00000000
#define FILE_HEADER_SPAN_LEN          0x00040000
#define FILE_HEADER_NEIWORKTYPE       0x0000011B

// Packet PCAP-header params
#define PACKET_HEADER_VERSION         0x00
#define PACKET_HEADER_RESERV          0x00
#define PACKET_HEADER_LENGTH          0x0024
#define PACKET_HEADER_CHANNEL_TYPE    0x0003
#define PACKET_HEADER_CHANNEL_LENGTH  0x0003
#define PACKET_HEADER_CHANNEL_PAGE    0x00
#define PACKET_HEADER_CHANNEL_PADDING 0x00
#define PACKET_HEADER_RSSI_TYPE       0x0001
#define PACKET_HEADER_RSSI_LENGTH     0x0004
#define PACKET_HEADER_LQI_TYPE        0x000A
#define PACKET_HEADER_LQI_LENGTH      0x0001
#define PACKET_HEADER_LQI_PADDING     {0x00, 0x00, 0x00}
#define PACKET_HEADER_FCS_TYPE        0x0000
#define PACKET_HEADER_FCS_LENGTH      0x0001
#define PACKET_HEADER_FCS             0x01
#define PACKET_HEADER_FCS_PADDING     {0x00, 0x00, 0x00}

typedef struct pcap_packet_main_info_s {
    uint8_t  version;
    uint8_t  reserved;
    uint16_t length;
} pcap_packet_main_info_t;

typedef struct pcap_packet_info_channel_s {
    uint16_t type;
    uint16_t length;
    uint16_t channel;
    uint8_t  page;
    uint8_t  padding;
} pcap_packet_info_channel_t;

typedef struct pcap_packet_info_rssi_s {
    uint16_t type;
    uint16_t length;
    int32_t rssi;
} pcap_packet_info_rssi_t;
typedef struct pcap_packet_info_lqi_s {
    uint16_t type;
    uint16_t length;
    uint8_t  lqi;
    uint8_t  padding[3];
} pcap_packet_info_lqi_t;

typedef struct pcap_info_fcs_s {
    uint16_t type;
    uint16_t length;
    uint8_t  fcs;
    uint8_t  padding[3];
} pcap_info_fcs_t;

typedef struct pcap_packet_info_header_s {
    pcap_packet_main_info_t    header_info;
    pcap_packet_info_channel_t channel_info;
    pcap_packet_info_rssi_t    rssi_info;
    pcap_packet_info_lqi_t     lqi_info;
    pcap_info_fcs_t            fcs_info;
} pcap_packet_info_header_t;

// PCAP packet header
typedef struct pcap_packet_header_s {
    uint32_t                  timestamp_sec;   // timestamp seconds
    uint32_t                  timestamp_usec;  // timestamp microseconds
    uint32_t                  incl_length;     // number of octets of packet saved in file
    uint32_t                  orig_length;     // actual length of packet
    pcap_packet_info_header_t packet_info;
} pcap_packet_header_t;

// PCAP packet format
typedef struct pcap_packet_s {
    pcap_packet_header_t header;
    uint8_t payload[MAX_SOURCE_FRAME_LEN];
} pcap_packet_t;

// Main PCAP-header
typedef struct pcap_main_file_header_s {
    uint32_t magic_number;   // magic number
    uint16_t version_major;  // major version number
    uint16_t version_minor;  // minor version number
    int32_t  reserv_1;       // GMT to local correction
    uint32_t reserv_2;       // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets, in octets
    uint32_t network;        // data link type
} pcap_main_file_header_t;


#endif