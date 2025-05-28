#include "netflow/packet/ip.h"
#include <stddef.h> // For NULL and offsetof

// Standard IPv4 header checksum algorithm
// Ref: RFC 1071 for checksum calculation
uint16_t calculate_ip_header_checksum(const IpHeader* ip_header_ptr) {
    if (ip_header_ptr == NULL) {
        return 0; // Or handle error appropriately
    }

    // The header length is in 32-bit words.
    // Checksum is calculated over the header only.
    int header_len_words = ip_header_ptr->ihl;
    
    uint32_t sum = 0;
    const uint16_t* word_ptr = (const uint16_t*)ip_header_ptr;

    // Sum all 16-bit words in the header
    // The checksum field itself (ip_header_ptr->check) should be treated as zero during calculation.
    for (int i = 0; i < header_len_words * 2; ++i) { // header_len_words * 2 gives number of 16-bit words
        // Check if the current word is part of the checksum field.
        // The checksum field is at an offset of 10 bytes (5 words of 16-bit) from the start.
        if (i == (offsetof(IpHeader, check) / sizeof(uint16_t))) {
            // Skip the original checksum field, treat it as 0.
            // The sum is already initialized to 0, so adding 0 is effectively skipping.
            // sum += 0; 
        } else {
            sum += word_ptr[i];
        }
    }

    // Add carry bits: if the sum overflows 16 bits, add the carry to the LSBs
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement of the sum
    return (uint16_t)(~sum);
}
