#ifndef NETFLOW_PLUS_PLUS_PROTO_ETHERNET_HPP
#define NETFLOW_PLUS_PLUS_PROTO_ETHERNET_HPP

#include "netflow_plus_plus/core/types.hpp" // For MacAddress
#include <cstdint> // For uint16_t
#include <array>   // For std::array

// Potentially include for ntohs/htons if handling network byte order explicitly
// #include <arpa/inet.h> // For Linux/macOS
// or <winsock2.h> for Windows, though direct struct mapping is often okay
// if the struct layout matches the wire protocol and endianness is handled.

namespace netflow_plus_plus {
namespace proto {

/**
 * @brief Represents an Ethernet II header.
 *
 * This struct directly maps the layout of an Ethernet II frame header.
 * MAC addresses are stored as arrays of bytes. EtherType is in host byte order
 * after potential conversion (e.g., ntohs) if read from network data.
 */
#pragma pack(push, 1) // Ensure structure is packed (no padding)
struct EthernetHeader {
    core::MacAddress destination_mac;
    core::MacAddress source_mac;
    uint16_t ether_type; // Stored in host byte order if converted from network order.
                        // Common values: 0x0800 for IPv4, 0x86DD for IPv6, 0x8100 for VLAN.

    /**
     * @brief Gets the EtherType in host byte order.
     * Assumes ether_type field is already in host byte order or converted.
     * If reading directly from a network buffer where EtherType is in network byte order,
     * ntohs() should be applied before storing or when accessing.
     */
    uint16_t get_ether_type() const {
        // return ntohs(ether_type); // If ether_type was stored in network byte order
        return ether_type; // Assuming it's already in host byte order
    }

    /**
     * @brief Sets the EtherType. Input should be in host byte order.
     * If writing to a network buffer, this value might need conversion to network byte order (htons).
     */
    void set_ether_type(uint16_t type) {
        // ether_type = htons(type); // If ether_type needs to be stored in network byte order
        ether_type = type; // Assuming storing in host byte order
    }
};
#pragma pack(pop) // Restore default packing

// Define some common EtherType values (host byte order)
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_MPLS = 0x8847;

} // namespace proto
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_PROTO_ETHERNET_HPP
