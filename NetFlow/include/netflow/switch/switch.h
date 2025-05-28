#ifndef NETFLOW_SWITCH_SWITCH_H_
#define NETFLOW_SWITCH_SWITCH_H_

#include "netflow/core/flow_table.h"
#include "netflow/protocols/arp.h"
// #include "netflow/protocols/icmp.h" // ICMP processing will be part of packet_processing_handler_
#include "netflow/packet/ethernet.h"
#include "netflow/packet/ip.h"
#include "netflow/packet/Packet.h" // For Packet object

#include "netflow/switch/ForwardingDatabase.h"
#include "netflow/switch/VlanManager.h"
#include "netflow/switch/StpManager.h"

#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <functional>
#include <map>
#include <memory>

// Remove old assumptions about ethernet.h and ip.h as they are now implemented.

namespace netflow {
namespace switch_logic {

// Structure to hold per-interface state (IP/MAC configuration)
// Physical port properties like STP state, VLAN config are managed by respective managers.
struct InterfaceInfo {
  uint32_t ip_address; // Host byte order, used for L3 interface functionality
  std::array<uint8_t, 6> mac_address; // Used for L3 interface functionality and possibly bridge MAC
  std::string name;
  int id; // Unique identifier for the interface, matches port_id used by managers

  InterfaceInfo() : ip_address(0), id(-1) {}
  InterfaceInfo(uint32_t ip, const std::array<uint8_t, 6>& mac, const std::string& n, int i)
      : ip_address(ip), mac_address(mac), name(n), id(i) {}
};

class Switch {
 public:
  explicit Switch(int num_ports);

  // Component Accessors
  ForwardingDatabase& fdb();
  VlanManager& vlan_manager();
  StpManager& stp_manager();

  // Configuration
  void add_interface(int interface_id, const std::string& name,
                     uint32_t ip_address, // Host byte order
                     const std::array<uint8_t, 6>& mac_address);
  
  void set_send_packet_callback(
      std::function<void(int interface_id, const std::vector<uint8_t>& packet_data)> cb);

  void set_packet_handler(
      std::function<void(const Packet& pkt, uint32_t ingress_port)> handler);

  // Operations
  // Renamed original receive_packet to handle_raw_frame and made it public for external call
  // It's the entry point for raw frames into the switch.
  void handle_raw_frame(int interface_id, const uint8_t* data, size_t length);

  void forward_packet(const Packet& pkt, uint32_t egress_port);
  void flood_packet(const Packet& pkt, uint32_t ingress_port); 
  
  void start(); // Placeholder for switch operation start (e.g., STP timers)

 private:
  int num_ports_;
  
  // L2 Components
  // Note: ForwardingDatabase, VlanManager, StpManager are in global namespace as per their headers.
  ForwardingDatabase fdb_;
  VlanManager vlan_manager_;
  StpManager stp_manager_;

  // Interface specific L3 info (IP, MAC of the switch's L3 interfaces)
  std::map<uint32_t, InterfaceInfo> interfaces_; // Changed key to uint32_t
  
  // Callback for sending raw packets out of a physical port
  std::function<void(int interface_id, const std::vector<uint8_t>& packet_data)> send_packet_callback_;
  
  // Callback for higher-level packet processing (L2 forwarding, L3 routing, etc.)
  std::function<void(const Packet& pkt, uint32_t ingress_port)> packet_processing_handler_;

  // Retained for potential direct L3/L4 processing if not fully handled by packet_processing_handler_
  // Or if packet_processing_handler_ itself needs to interact with these.
  netflow::core::FlowTable flow_table_; 
  netflow::protocols::arp::ArpCache arp_cache_; 

  // Default packet processing logic
  void default_packet_processor(const Packet& pkt, uint32_t ingress_port);

  // Helper methods for default_packet_processor
  InterfaceInfo* get_interface_info(uint32_t port_id); // Returns non-const to allow potential modification if needed by other logic later
  void handle_arp_packet(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id, const InterfaceInfo* ingress_if_info);
  void handle_ip_packet_for_us(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id, const InterfaceInfo* ingress_if_info);
  void route_ip_packet(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id);

public: // Test-specific helpers - public for access from test suite
    // Define MACAddress here if not globally accessible through includes, or ensure ForwardingDatabase.h is included.
    // It is included, so std::array<uint8_t, 6> is fine.
    void add_flow_entry_for_test(const netflow::core::Flow& flow, int action_out_port_id);
    void add_arp_entry_for_test(uint32_t ip_address_host_order, const std::array<uint8_t, 6>& mac);
    void clear_flow_table_for_test();
    void clear_arp_cache_for_test();
};

}  // namespace switch_logic
}  // namespace netflow

#endif  // NETFLOW_SWITCH_SWITCH_H_
