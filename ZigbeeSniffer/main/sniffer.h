#ifndef SNIFFER_H
#define SNIFFER_H

#include <string.h>
#include "pcap_types.h"

// UART config
#define UART_NUM             UART_NUM_1
#define UART_BAUD_RATE       921600
#define UART_TX_PIN          18
#define UART_RX_PIN          19

#define ZIGBEE_CHANNEL       16   // Sniffed zigbee-channel 
#define BUF_SIZE             1024 // Max len of massage in uart
#define SNIFFER_DEBUG_MODE   1    // Debug-mod switcher

#endif