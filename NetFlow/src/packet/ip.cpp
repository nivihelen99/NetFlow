#include "netflow/packet/ip.h"
#include <cstdint>
#include <arpa/inet.h> // For ntohs, htons

// Note: <numeric> for std::accumulate is not used in this implementation.

namespace netflow {
namespace packet {

// Calculates the IPv4 header checksum.
// ip_header_ptr should point to the beginning of the IP header.
// The checksum field in the header (ip_header_ptr->check) MUST be zero
// before calling this function for calculation.
// If verifying a received checksum, the received checksum should be in place.
uint16_t calculate_ip_header_checksum(const IpHeader* ip_header_ptr) {
    if (!ip_header_ptr) {
        return 0; // Or some error indication
    }

    size_t header_words = ip_header_ptr->ihl; // ihl is the number of 4-byte words
    if (header_words < 5) { // Minimum 5 words (20 bytes) for a valid IP header
        return 0; // Invalid header, cannot calculate checksum
    }
    // size_t header_bytes = header_words * 4; // Not directly used in word-based sum

    uint32_t sum = 0;
    const uint16_t* half_word_ptr = reinterpret_cast<const uint16_t*>(ip_header_ptr);

    // Sum all 16-bit half-words of the header.
    // The ip_header_ptr->check field is part of this sum. For calculation, it must be 0.
    // For verification, it contains the received checksum.
    for (size_t i = 0; i < header_words * 2; ++i) { // header_words * 2 gives number of 16-bit (uint16_t) words
        sum += ntohs(half_word_ptr[i]); // Add in host byte order to handle carries correctly
    }
    
    // Add carry-overs: if sum is greater than 0xFFFF, add the high 16 bits to the low 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement of the sum
    uint16_t checksum = ~static_cast<uint16_t>(sum);
    
    // Return in network byte order
    return htons(checksum);
}

}  // namespace packet
}  // namespace netflow
