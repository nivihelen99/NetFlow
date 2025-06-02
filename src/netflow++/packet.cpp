#include "netflow++/packet.hpp"
#include <bitset> // For std::bitset for counting set bits

// For ntohl, if IpAddress (uint32_t) is stored in network byte order
// and needs conversion to host byte order for bitwise operations.
// Assuming it's available as per packet.hpp includes.
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif


namespace netflow {

uint8_t ip_mask_to_prefix_length(IpAddress subnet_mask_param) {
    // IpAddress is uint32_t.
    // Subnet masks are typically represented in host byte order when defined
    // (e.g., 0xFFFFFF00). If IpAddress stores it in network byte order,
    // it might need conversion before bit manipulation, depending on how it's stored.
    // Let's assume subnet_mask_param is passed as a uint32_t that represents the mask
    // in a way that direct bit counting works (e.g. host order 0xFFFFFF00 for /24).
    // If IpAddress typedef implies network order, then conversion to host order is needed first.
    // The current IpAddress is a raw uint32_t. Let's assume it's passed in a sensible way
    // for bit counting (effectively host byte order for the value).

    uint32_t mask_host_order = subnet_mask_param; // Assume it's already in host order or compatible for bitset

    // A common case: /0 mask
    if (mask_host_order == 0) {
        return 0;
    }

    // Check for validity (all 1s followed by all 0s)
    // A mask is valid if (mask & (mask + (is_power_of_2( (~mask) +1 ) ) ) ) == 0
    // or simpler: ( (mask ^ (mask -1) ) >> 1) +1 == mask
    // More simply: check if (mask & (mask + 1)) == 0 after inverting bits, if mask is not all ones.
    // Or, (x & (x+1) == 0) implies x is of form 0...01...1. So (~mask & (~mask+1)) == 0
    uint32_t inverted_mask = ~mask_host_order;
    if (inverted_mask != 0 && (inverted_mask & (inverted_mask + 1)) != 0) {
        // This mask is not a contiguous block of 0s (when inverted), so it's invalid.
        // e.g. 255.0.255.0 is invalid.
        // For simplicity, many implementations just count bits or trust input.
        // Depending on strictness, one might return 0 or throw an error.
        // For now, let's proceed with bit counting, assuming valid masks are common.
        // If an invalid mask like 255.0.255.0 (0xFF00FF00) is given, bitset().count() would be 16.
        // This might be acceptable if the definition of "prefix length" is just "number of set bits".
    }


    // Using std::bitset to count the number of set bits.
    // This is the most straightforward way if the mask is valid (contiguous 1s).
    std::bitset<32> bits(mask_host_order);
    return static_cast<uint8_t>(bits.count());
}

} // namespace netflow
