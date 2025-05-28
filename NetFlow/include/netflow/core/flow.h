#ifndef NETFLOW_CORE_FLOW_H_
#define NETFLOW_CORE_FLOW_H_

#include <cstdint>
#include <string>

namespace netflow {
namespace core {

class Flow {
 public:
  Flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
       uint16_t dst_port, uint8_t protocol);

  uint32_t get_src_ip() const;
  uint32_t get_dst_ip() const;
  uint16_t get_src_port() const;
  uint16_t get_dst_port() const;
  uint8_t get_protocol() const;

  bool operator==(const Flow& other) const;

 private:
  uint32_t src_ip_;
  uint32_t dst_ip_;
  uint16_t src_port_;
  uint16_t dst_port_;
  uint8_t protocol_;
};

}  // namespace core
}  // namespace netflow

// Forward declaration (if FlowTable needs to know about Flow and vice-versa, though not strictly needed here)
// class FlowTable; 

// Hash function for Flow (needed for std::unordered_map)
namespace std {
    template <>
    struct hash<netflow::core::Flow> {
        std::size_t operator()(const netflow::core::Flow& flow) const;
    };
}

#endif  // NETFLOW_CORE_FLOW_H_
