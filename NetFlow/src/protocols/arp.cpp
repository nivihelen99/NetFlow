#include "netflow/protocols/arp.h"
#include <chrono>
#include <vector>
#include <cstring> // For memcpy
#include <arpa/inet.h> // For htons, htonl, ntohs, ntohl

namespace netflow {
namespace protocols {
namespace arp {

ArpCache::ArpCache(std::chrono::seconds timeout) : cache_timeout_(timeout) {}

void ArpCache::add_entry(uint32_t ip, const std::array<uint8_t, 6>& mac) {
  cache_[ip] = {mac, std::chrono::steady_clock::now()};
}

bool ArpCache::lookup(uint32_t ip, std::array<uint8_t, 6>& mac_out) {
  auto it = cache_.find(ip);
  if (it == cache_.end()) {
    return false;
  }

  if (std::chrono::steady_clock::now() - it->second.timestamp > cache_timeout_) {
    cache_.erase(it); // Erase expired entry
    return false;
  }

  mac_out = it->second.mac_address; // std::array supports direct assignment
  return true;
}

void ArpCache::cleanup_expired() {
  auto now = std::chrono::steady_clock::now();
  for (auto it = cache_.begin(); it != cache_.end(); /* no increment here */) {
    if (now - it->second.timestamp > cache_timeout_) {
      it = cache_.erase(it); // erase returns the iterator to the next element
    } else {
      ++it;
    }
  }
}

// Function implementations
std::vector<uint8_t> create_arp_request(
    const std::array<uint8_t, 6>& sender_mac,
    uint32_t sender_ip,
    uint32_t target_ip) {
  ArpHeader header;
  header.hrd_type = htons(ARP_HRD_ETHERNET);
  header.pro_type = htons(ARP_PRO_IPV4);
  header.hrd_len = ARP_HLN_ETHERNET;
  header.pro_len = ARP_PLN_IPV4;
  header.opcode = htons(ARP_OP_REQUEST);
  header.sender_mac = sender_mac;
  header.sender_ip = htonl(sender_ip);
  // Target MAC is broadcast (all zeros often works, but all FFs is more correct for Ethernet broadcast)
  // However, the problem description specifically said {0,0,0,0,0,0} for target_mac in request.
  header.target_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
  header.target_ip = htonl(target_ip);

  std::vector<uint8_t> packet(sizeof(ArpHeader));
  std::memcpy(packet.data(), &header, sizeof(ArpHeader));
  return packet;
}

std::vector<uint8_t> create_arp_reply(
    const std::array<uint8_t, 6>& sender_mac, // Our MAC (who is replying)
    uint32_t sender_ip,                       // Our IP (who is replying)
    const std::array<uint8_t, 6>& target_mac, // MAC of the original requester
    uint32_t target_ip) {                     // IP of the original requester
  ArpHeader header;
  header.hrd_type = htons(ARP_HRD_ETHERNET);
  header.pro_type = htons(ARP_PRO_IPV4);
  header.hrd_len = ARP_HLN_ETHERNET;
  header.pro_len = ARP_PLN_IPV4;
  header.opcode = htons(ARP_OP_REPLY);
  header.sender_mac = sender_mac;
  header.sender_ip = htonl(sender_ip);
  header.target_mac = target_mac;
  header.target_ip = htonl(target_ip);

  std::vector<uint8_t> packet(sizeof(ArpHeader));
  std::memcpy(packet.data(), &header, sizeof(ArpHeader));
  return packet;
}

ArpProcessResult process_arp_packet(
    ArpCache& cache,
    const uint8_t* packet_data,
    size_t packet_len,
    uint32_t our_ip,
    const std::array<uint8_t, 6>& our_mac,
    std::vector<uint8_t>& reply_packet_out) {
  if (!packet_data || packet_len < sizeof(ArpHeader)) {
    return ArpProcessResult::NONE;
  }

  const ArpHeader* arp_header = reinterpret_cast<const ArpHeader*>(packet_data);

  // Validate header fields
  if (ntohs(arp_header->hrd_type) != ARP_HRD_ETHERNET ||
      ntohs(arp_header->pro_type) != ARP_PRO_IPV4 ||
      arp_header->hrd_len != ARP_HLN_ETHERNET ||
      arp_header->pro_len != ARP_PLN_IPV4) {
    return ArpProcessResult::NONE;
  }

  uint32_t arp_sender_ip_host = ntohl(arp_header->sender_ip);
  uint32_t arp_target_ip_host = ntohl(arp_header->target_ip);

  // Always add/update the sender's IP/MAC to the ARP cache,
  // but only if sender IP is not zero (which can happen in some gratuitous ARP scenarios not handled here)
  if (arp_sender_ip_host != 0) {
    cache.add_entry(arp_sender_ip_host, arp_header->sender_mac);
  }


  uint16_t opcode = ntohs(arp_header->opcode);

  if (opcode == ARP_OP_REQUEST) {
    if (arp_target_ip_host == our_ip) {
      // It's a request for our IP
      reply_packet_out = create_arp_reply(our_mac, our_ip, arp_header->sender_mac, arp_sender_ip_host);
      return ArpProcessResult::REQUEST_HANDLED_REPLY_SENT;
    }
  } else if (opcode == ARP_OP_REPLY) {
    // Cache update for reply sender was already done above.
    // Additional logic could be here if we wanted to check if this reply
    // was for a request we sent, but for now, just updating cache is enough.
    return ArpProcessResult::REPLY_RECEIVED_CACHE_UPDATED;
  }

  return ArpProcessResult::NONE;
}

}  // namespace arp
}  // namespace protocols
}  // namespace netflow
