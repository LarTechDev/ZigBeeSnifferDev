#ifndef ADAPTER_H
#define ADAPTER_H

#include <vector>
#include <queue>

#define WIRESHARK_ADAPTER_NAME   (string)"Zigbee Sniffer"
#define PROGRAMM_VERSION          2.0
#define USE_QUI_MENU              1

#define UART_BUFFER_SIZE         1024
#define MAX_SERIAL_NUMBER        255

// Default serial-port params
#define DEFAULT_SERIAL_PORT       "5"
#define DEFAULT_BAUND_RATE        "921600"
#define DEFAULT_BYTE_SIZE         "8"
#define DEFAULT_STOP_BITS         "1"
#define DEFAULT_PARITY            "NONE"
#define DEFAULT_CHANNEL           "16"
#define DEFAULT_FRAME_DELAY       "15"

// Main PCAP-header params
#define FILE_HEADER_MAGIC_NUMBER  0xA1B2C3D4
#define FILE_HEADER_VERSION_MAJOR 0x0002
#define FILE_HEADER_VERSION_MINOR 0x0004
#define FILE_HEADER_RESERVED_1    0x00000000
#define FILE_HEADER_RESERVED_2    0x00000000
#define FILE_HEADER_SPAN_LEN      0x00040000
#define FILE_HEADER_NEIWORKTYPE   0x0000011B


typedef unsigned char typeFrameByte;
typedef std::vector<typeFrameByte> typeFrameVector;
typedef std::queue< typeFrameVector > typeFrameQueue;

#endif