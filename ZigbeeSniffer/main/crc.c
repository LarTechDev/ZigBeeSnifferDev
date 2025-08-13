#include "crc.h"

uint16_t 
get_crc(uint8_t *data, uint16_t len) {
    uint16_t crc = 0x0000;
	while (len--) {
		crc = (crc >> 8) ^ crc_table[(crc ^ (*(data++))) & 0xff];
	}
	return crc;
}