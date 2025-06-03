#include "netflow++/packet.hpp"
#include "netflow++/byte_swap.hpp" // For ntohl

namespace netflow {

// Utility function to convert an IPv4 subnet mask to prefix length
// A simple stub implementation. A real one would count contiguous high bits.
uint8_t ip_mask_to_prefix_length(IpAddress subnet_mask) {
    if (subnet_mask == 0) return 0; // Not a valid mask or /0

    uint32_t mask = ntohl(subnet_mask); // Ensure host byte order for bitwise operations
    uint8_t prefix_length = 0;
    bool zero_encountered = false;
    for (int i = 31; i >= 0; --i) {
        if ((mask >> i) & 1) { // If bit is 1
            if (zero_encountered) {
                return 0; // Invalid mask (e.g., 255.0.255.0), non-contiguous
            }
            prefix_length++;
        } else { // If bit is 0
            zero_encountered = true;
        }
    }
    // Check for masks like 0.0.0.1 (invalid)
    if (prefix_length == 0 && subnet_mask != 0) return 0;
    return prefix_length;
}

} // namespace netflow
