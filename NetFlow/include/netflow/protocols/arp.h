#ifndef NETFLOW_PROTOCOLS_ARP_H_
#define NETFLOW_PROTOCOLS_ARP_H_

#include <cstdint>
#include <array>
#include <vector> // Although not used in this revision, it was in the plan. Keeping for consistency for now or future use.
#include <chrono>
#include <unordered_map>

namespace netflow {
namespace protocols {
namespace arp {

// ARP constants
constexpr uint16_t ARP_HRD_ETHERNET = 1;
constexpr uint16_t ARP_PRO_IPV4 = 0x0800;
constexpr uint8_t ARP_HLN_ETHERNET = 6;
constexpr uint8_t ARP_PLN_IPV4 = 4;
constexpr uint16_t ARP_OP_REQUEST = 1;
constexpr uint16_t ARP_OP_REPLY = 2;

// ARP Header structure
struct ArpHeader {
  uint16_t hrd_type;
  uint16_t pro_type;
  uint8_t hrd_len;
  uint8_t pro_len;
  uint16_t opcode;
  std::array<uint8_t, 6> sender_mac;
  uint32_t sender_ip;
  std::array<uint8_t, 6> target_mac;
  uint32_t target_ip;
} __attribute__((packed));

// ARP Cache Entry structure
struct ArpCacheEntry {
  std::array<uint8_t, 6> mac_address;
  std::chrono::steady_clock::time_point timestamp;
};

// ARP Cache class
class ArpCache {
 public:
  ArpCache(std::chrono::seconds timeout = std::chrono::seconds(300));
  void add_entry(uint32_t ip, const std::array<uint8_t, 6>& mac);
  bool lookup(uint32_t ip, std::array<uint8_t, 6>& mac_out);
  void cleanup_expired();

 private:
  std::unordered_map<uint32_t, ArpCacheEntry> cache_;
  std::chrono::seconds cache_timeout_;
};

// Enum to represent the result of processing an ARP packet
enum class ArpProcessResult {
    NONE, // No action or not an ARP packet for us
    REQUEST_HANDLED_REPLY_SENT, // Processed a request for us, reply was generated
    REPLY_RECEIVED_CACHE_UPDATED // Processed a reply, cache was updated
};

// Function declarations
std::vector<uint8_t> create_arp_request(
    const std::array<uint8_t, 6>& sender_mac,
    uint32_t sender_ip,
    uint32_t target_ip
);

std::vector<uint8_t> create_arp_reply(
    const std::array<uint8_t, 6>& sender_mac,
    uint32_t sender_ip,
    const std::array<uint8_t, 6>& target_mac,
    uint32_t target_ip
);

ArpProcessResult process_arp_packet(
    ArpCache& cache, // ARP cache to update/use
    const uint8_t* packet_data, // Raw ARP packet bytes
    size_t packet_len,          // Length of the ARP packet
    uint32_t our_ip,            // IP address of the interface receiving this packet
    const std::array<uint8_t, 6>& our_mac, // MAC address of the interface
    std::vector<uint8_t>& reply_packet_out // If a reply is generated, it's put here
);

}  // namespace arp
}  // namespace protocols
}  // namespace netflow

#endif  // NETFLOW_PROTOCOLS_ARP_H_
