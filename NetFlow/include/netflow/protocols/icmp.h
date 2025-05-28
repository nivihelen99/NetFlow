#ifndef NETFLOW_PROTOCOLS_ICMP_H_
#define NETFLOW_PROTOCOLS_ICMP_H_

#include <cstdint>
#include <vector>
#include <string>    // For potential future use, e.g. logging
#include <algorithm> // For std::copy, std::fill, etc.

// For htons, ntohs (should be included in the .cpp, but sometimes placed in .h for convenience)
// #include <arpa/inet.h>

namespace netflow {
namespace protocols {
namespace icmp {

// ICMP message type constants
constexpr uint8_t ICMP_TYPE_ECHO_REPLY = 0;
constexpr uint8_t ICMP_TYPE_DEST_UNREACH = 3;
constexpr uint8_t ICMP_TYPE_ECHO_REQUEST = 8;

// ICMP destination unreachable codes (for type 3)
constexpr uint8_t ICMP_CODE_NET_UNREACH = 0;
constexpr uint8_t ICMP_CODE_HOST_UNREACH = 1;
constexpr uint8_t ICMP_CODE_PROTO_UNREACH = 2;
constexpr uint8_t ICMP_CODE_PORT_UNREACH = 3;

// ICMP Header structure
struct IcmpHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t rest_of_header; // For echo, this is identifier (2 bytes) and sequence number (2 bytes).
                           // For others, might be unused or different.
} __attribute__((packed));

// ICMP Echo Detail structure (overlay for rest_of_header in echo messages)
// This is primarily for conceptual understanding; access is typically by pointer casting.
struct IcmpEchoDetail {
  uint16_t identifier;
  uint16_t sequence_number;
} __attribute__((packed));

// Utility function to calculate ICMP checksum
uint16_t calculate_icmp_checksum(const uint8_t* data, size_t length);

// Functions to create ICMP packets

// Creates an ICMP Echo Request or Echo Reply packet
std::vector<uint8_t> create_icmp_echo(
    uint8_t type, // ICMP_TYPE_ECHO_REQUEST or ICMP_TYPE_ECHO_REPLY
    uint16_t identifier,
    uint16_t sequence_number,
    const std::vector<uint8_t>& payload);

// Creates an ICMP Destination Unreachable packet
// Assumes original_ip_header points to a standard IPv4 header.
// Assumes original_ip_payload points to the first 8 bytes of the original IP payload.
// The length of original_ip_header data to be copied is assumed to be 20 bytes.
std::vector<uint8_t> create_icmp_dest_unreachable(
    uint8_t code, // e.g., ICMP_CODE_HOST_UNREACH
    const uint8_t* original_ip_header, // Pointer to the start of the original IP header (at least 20 bytes)
    const uint8_t* original_ip_payload // Pointer to the first 8 bytes of the original IP payload
);

// Enum to represent the result of processing an ICMP packet
enum class IcmpProcessResult {
  NONE,
  ECHO_REQUEST_RECEIVED_REPLY_GENERATED,
  ECHO_REPLY_RECEIVED,
  DEST_UNREACHABLE_RECEIVED,
  INVALID_CHECKSUM
};

// Function to process an incoming ICMP packet
IcmpProcessResult process_icmp_packet(
    const uint8_t* icmp_packet_data, // Raw ICMP packet (starts with ICMP header)
    size_t icmp_packet_len,
    // IP header information of the packet carrying this ICMP message (not used currently but good for API design)
    // uint32_t source_ip, // Source IP of the incoming packet (network byte order)
    // uint32_t dest_ip,   // Destination IP of the incoming packet (network byte order)
    // Output parameter for generated reply
    std::vector<uint8_t>& reply_icmp_packet_out // If an echo reply is generated, its *full ICMP packet* is put here
);

}  // namespace icmp
}  // namespace protocols
}  // namespace netflow

#endif  // NETFLOW_PROTOCOLS_ICMP_H_
