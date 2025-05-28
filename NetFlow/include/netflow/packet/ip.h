#ifndef NETFLOW_PACKET_IP_H_
#define NETFLOW_PACKET_IP_H_

#include <cstdint>

namespace netflow {
namespace packet {

// IP protocol constants
const uint8_t IPPROTO_ICMP = 1;
const uint8_t IPPROTO_TCP = 6;
const uint8_t IPPROTO_UDP = 17;

// IP Header structure
struct IpHeader {
  uint8_t ihl : 4;       // Internet Header Length (in 4-byte words)
  uint8_t version : 4; // Version (should be 4 for IPv4)
  uint8_t tos;          // Type of Service
  uint16_t tot_len;     // Total Length (header + data), network byte order
  uint16_t id;          // Identification, network byte order
  uint16_t frag_off;    // Fragment Offset + Flags, network byte order
  uint8_t ttl;          // Time to Live
  uint8_t protocol;     // Protocol (e.g., TCP, UDP, ICMP)
  uint16_t check;       // Header Checksum, network byte order
  uint32_t saddr;       // Source IP Address, network byte order
  uint32_t daddr;       // Destination IP Address, network byte order
} __attribute__((packed));

// Calculates the IPv4 header checksum.
// ip_header_ptr should point to the beginning of the IP header.
// The checksum field in the header should be set to 0 before calling this.
uint16_t calculate_ip_header_checksum(const IpHeader* ip_header_ptr);

}  // namespace packet
}  // namespace netflow

#endif  // NETFLOW_PACKET_IP_H_
