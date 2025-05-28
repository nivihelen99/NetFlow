#include "netflow/core/flow.h"
#include <functional> // Required for std::hash

namespace netflow {
namespace core {

Flow::Flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
           uint16_t dst_port, uint8_t protocol)
    : src_ip_(src_ip),
      dst_ip_(dst_ip),
      src_port_(src_port),
      dst_port_(dst_port),
      protocol_(protocol) {}

uint32_t Flow::get_src_ip() const { return src_ip_; }

uint32_t Flow::get_dst_ip() const { return dst_ip_; }

uint16_t Flow::get_src_port() const { return src_port_; }

uint16_t Flow::get_dst_port() const { return dst_port_; }

uint8_t Flow::get_protocol() const { return protocol_; }

bool Flow::operator==(const Flow& other) const {
  return src_ip_ == other.src_ip_ && dst_ip_ == other.dst_ip_ &&
         src_port_ == other.src_port_ && dst_port_ == other.dst_port_ &&
         protocol_ == other.protocol_;
}

}  // namespace core
}  // namespace netflow

// Hash function implementation for Flow
namespace std {
std::size_t hash<netflow::core::Flow>::operator()(
    const netflow::core::Flow& flow) const {
  std::size_t h1 = std::hash<uint32_t>()(flow.get_src_ip());
  std::size_t h2 = std::hash<uint32_t>()(flow.get_dst_ip());
  std::size_t h3 = std::hash<uint16_t>()(flow.get_src_port());
  std::size_t h4 = std::hash<uint16_t>()(flow.get_dst_port());
  std::size_t h5 = std::hash<uint8_t>()(flow.get_protocol());

  // A common way to combine hash values.
  // The specific constants are not critical but should ideally be primes.
  // The left shifts are to spread out the bits of the component hashes.
  std::size_t seed = 0;
  seed ^= h1 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= h4 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= h5 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  return seed;
}
}  // namespace std
