#include "sniffer.h"
#include "esp_ieee802154.h"
#include "freertos/FreeRTOS.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_check.h"
#include "nvs_flash.h"
#include "crc.h"

static const char *TAG = "ZIGBEE_SNIFFER";

#define FRAMES_BUFFER_LEN 64
static uint8_t rx_frame[FRAMES_BUFFER_LEN * MAX_SOURCE_FRAME_LEN];
static esp_ieee802154_frame_info_t rx_frame_info[FRAMES_BUFFER_LEN];
static uint16_t now_buffer_size = 0;

static volatile bool radio_active = false;

void 
pcap_send_data(const uint8_t *data, size_t len) {
#if SNIFFER_DEBUG_MODE
    printf("FRAME:");
    for(int i = 0; i < len; i++) {
        printf(" %02x", *(data + i));
    }
    printf("\n");

    printf("Sending %d bytes to UART\n", len);
#endif
    uart_write_bytes(UART_NUM, (const char *)data, len);
}

void 
check_radio_status(void) {
    printf("Radio state: %d\n", esp_ieee802154_get_state());
    printf("Recent RSSI: %d\n", esp_ieee802154_get_recent_rssi());
    printf("Recent LQI: %d\n", esp_ieee802154_get_recent_lqi());
    printf("Promiscuous mode: %s\n", esp_ieee802154_get_promiscuous() ? "ON" : "OFF");
}

void 
quality_task(void *pvParameters) {
    while(1) {
        check_radio_status();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void 
frame_processor_task(void *pvParameters) {
    uint8_t lqi_padding[3] = PACKET_HEADER_LQI_PADDING;
    uint8_t fcs_padding[3] = PACKET_HEADER_LQI_PADDING;


    pcap_packet_t packet;

    packet.header.packet_info.header_info.version  = PACKET_HEADER_VERSION;
    packet.header.packet_info.header_info.reserved = PACKET_HEADER_RESERV;
    packet.header.packet_info.header_info.length   = PACKET_HEADER_LENGTH;
    packet.header.packet_info.channel_info.type    = PACKET_HEADER_CHANNEL_TYPE;
    packet.header.packet_info.channel_info.length  = PACKET_HEADER_CHANNEL_LENGTH;
    packet.header.packet_info.channel_info.channel = ZIGBEE_CHANNEL;
    packet.header.packet_info.channel_info.page    = PACKET_HEADER_CHANNEL_PAGE;
    packet.header.packet_info.channel_info.padding = PACKET_HEADER_CHANNEL_PADDING;
    packet.header.packet_info.rssi_info.type       = PACKET_HEADER_RSSI_TYPE;
    packet.header.packet_info.rssi_info.length     = PACKET_HEADER_RSSI_LENGTH;
    packet.header.packet_info.lqi_info.type        = PACKET_HEADER_LQI_TYPE;
    packet.header.packet_info.lqi_info.length      = PACKET_HEADER_LQI_LENGTH;
    packet.header.packet_info.fcs_info.type        = PACKET_HEADER_FCS_TYPE;
    packet.header.packet_info.fcs_info.length      = PACKET_HEADER_FCS_LENGTH;
    packet.header.packet_info.fcs_info.fcs         = PACKET_HEADER_FCS;

    memcpy(packet.header.packet_info.lqi_info.padding, lqi_padding, 3);
    memcpy(packet.header.packet_info.fcs_info.padding, fcs_padding, 3);

    while(1) {
        if(now_buffer_size) {
            uint8_t len = *rx_frame;
#if SNIFFER_DEBUG_MODE
            printf("Processing frame (№%d), len:%d, RSSI:%d\n", now_buffer_size, len, (*rx_frame_info).rssi);
#endif
            packet.header.timestamp_sec              = (*rx_frame_info).timestamp / 1000000;
            packet.header.timestamp_usec             = (*rx_frame_info).timestamp % 1000000;
            packet.header.incl_length                = len + PACKET_HEADER_LENGTH;
            packet.header.orig_length                = len + PACKET_HEADER_LENGTH;
            packet.header.packet_info.rssi_info.rssi = (*rx_frame_info).rssi;
            packet.header.packet_info.lqi_info.lqi   = (*rx_frame_info).lqi;

            memcpy(packet.payload, rx_frame + 1, len);
            uint16_t right_crc = get_crc(packet.payload, len - 2);
            memcpy(packet.payload + len - 2, (uint8_t *)&right_crc, 2);

            if (len) {
                pcap_send_data((uint8_t *)&packet, sizeof(packet.header) + len);
            }


            now_buffer_size--;
            memcpy(rx_frame, rx_frame + MAX_SOURCE_FRAME_LEN, MAX_SOURCE_FRAME_LEN * now_buffer_size);
        }
        vTaskDelay(2);
    }
}

void 
pcap_send_global_header(void) {
    pcap_main_file_header_t file_header = {
        .magic_number  = FILE_HEADER_MAGIC_NUMBER,
        .version_major = FILE_HEADER_VERSION_MAJOR,
        .version_minor = FILE_HEADER_VERSION_MINOR,
        .reserv_1      = FILE_HEADER_RESERVED_1,
        .reserv_2      = FILE_HEADER_RESERVED_2,
        .snaplen       = FILE_HEADER_SPAN_LEN,
        .network       = FILE_HEADER_NEIWORKTYPE,
    };
    pcap_send_data((uint8_t *)&file_header, sizeof(file_header));
}

void
init_zigbee_sniffer() {
    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(ZIGBEE_CHANNEL));
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_coordinator(false));
    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));
    ESP_ERROR_CHECK(esp_ieee802154_receive());
    
    pcap_send_global_header();
    
    radio_active = true;
}

void
esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    if(!radio_active) {
        return;
    }

    if(frame && frame_info && *frame < MAX_SOURCE_FRAME_LEN && *frame) {
        memcpy(rx_frame + now_buffer_size * MAX_SOURCE_FRAME_LEN, frame, *frame + 1);
        memcpy((uint8_t *)(rx_frame_info + now_buffer_size), (uint8_t *)frame_info, sizeof(rx_frame_info));
        now_buffer_size++;
    } 

    esp_ieee802154_receive_handle_done(frame);
}

void 
uart_init(void) {
    printf("Initializing UART on pins TX:%d RX:%d\n", UART_TX_PIN, UART_RX_PIN);

    uart_config_t uart_config = {
        .baud_rate  = UART_BAUD_RATE,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    int intr_alloc_flags = 0;

#if CONFIG_UART_ISR_IN_IRAM
    intr_alloc_flags = ESP_INTR_FLAG_IRAM;
#endif

    ESP_ERROR_CHECK(uart_param_config(UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_TX_PIN, UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM, BUF_SIZE * 2, BUF_SIZE * 2, 0, NULL, intr_alloc_flags));
}

void
set_sniffered_channel(uint8_t cnannel) {
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(cnannel));
    ESP_ERROR_CHECK(esp_ieee802154_receive());
}

void
handler_commands() {
    uint8_t RX_BUFFER[BUF_SIZE];
    size_t len;

    while(1) {
        len = uart_read_bytes(UART_NUM, RX_BUFFER, BUF_SIZE, 20 / ( ( TickType_t ) 1000 / CONFIG_FREERTOS_HZ));
        if (len) {
            switch(*RX_BUFFER) {
                case 0xCA:
                    uint8_t channel = *(RX_BUFFER + 1);
                    set_sniffered_channel(channel);
                    printf("Now Zigbee sniffer worked on channel %d\n", esp_ieee802154_get_channel());
                    break;
                default:
                    break;
            }
            uart_flush(UART_NUM);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void 
app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());

    uart_init();
    init_zigbee_sniffer();

    printf("Zigbee sniffer started on channel %d\n", esp_ieee802154_get_channel());
#if SNIFFER_DEBUG_MODE
    xTaskCreate(quality_task, "sniffer", 4096, NULL, 5, NULL);
#endif
    xTaskCreate(handler_commands, "commands_proc", 4096, NULL, 5, NULL);
    xTaskCreate(frame_processor_task, "frame_proc", 6120, NULL, 6, NULL);
}