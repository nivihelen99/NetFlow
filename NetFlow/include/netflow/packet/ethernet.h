#ifndef NETFLOW_PACKET_ETHERNET_H_
#define NETFLOW_PACKET_ETHERNET_H_

#include <cstdint>
#include <array>

namespace netflow {
namespace packet {

// EtherType constants
const uint16_t ETHERTYPE_IP = 0x0800;
const uint16_t ETHERTYPE_ARP = 0x0806;
const uint16_t ETHERTYPE_IPV6 = 0x86DD;

// Ethernet Header structure
struct EthernetHeader {
  std::array<uint8_t, 6> dest_mac;
  std::array<uint8_t, 6> src_mac;
  uint16_t type; // Network byte order
} __attribute__((packed));

}  // namespace packet
}  // namespace netflow

#endif  // NETFLOW_PACKET_ETHERNET_H_
