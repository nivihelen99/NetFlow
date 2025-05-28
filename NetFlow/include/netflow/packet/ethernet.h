#ifndef NETFLOW_PACKET_ETHERNET_H_
#define NETFLOW_PACKET_ETHERNET_H_

#include <cstdint>
#include <array>

#ifdef __cplusplus
extern "C" {
#endif

// EtherType constants
// These are C++ constants, so they are not part of the extern "C" block.
// However, their usage in C code would require equivalent #defines.
// For now, we assume they are used in C++ context or C code has alternatives.

// C-compatible Ethernet Header structure
typedef struct {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t type; // Network byte order
} EthernetHeader;

#ifdef __cplusplus
} // extern "C"
#endif

// C++ specific parts (if any) can remain here, outside extern "C"
// For example, the namespace and C++ specific constants if they were not C-compatible.
namespace netflow {
namespace packet {

// EtherType constants for C++
const uint16_t ETHERTYPE_IP = 0x0800;
const uint16_t ETHERTYPE_ARP = 0x0806;
const uint16_t ETHERTYPE_IPV6 = 0x86DD;

// C++ version of EthernetHeader using std::array (if needed for C++ specific code)
struct EthernetHeaderCpp {
  std::array<uint8_t, 6> dest_mac;
  std::array<uint8_t, 6> src_mac;
  uint16_t type; // Network byte order
} __attribute__((packed));

}  // namespace packet
}  // namespace netflow

#endif  // NETFLOW_PACKET_ETHERNET_H_


