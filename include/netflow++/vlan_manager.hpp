#ifndef NETFLOW_VLAN_MANAGER_HPP
#define NETFLOW_VLAN_MANAGER_HPP

#include "packet.hpp" // For Packet class and VlanHeader, MacAddress etc.
#include <cstdint>
#include <set>
#include <map>
#include <optional>
#include <stdexcept> // For invalid_argument

namespace netflow {

enum class PortType {
    ACCESS,
    TRUNK,
    HYBRID // Hybrid can be complex, often a mix of access and trunk behaviors
};

enum class PacketAction {
    FORWARD, // Packet is allowed to proceed
    DROP,    // Packet should be dropped
    CONSUME  // Packet is for the device itself (e.g. L3 processing, not implemented here)
};

struct VlanManagerConfig {
    // Global VLAN settings, if any, could go here.
    // For now, mainly a placeholder or for future expansion.
};

class VlanManager {
public:
    struct PortConfig {
        PortType type = PortType::ACCESS;
        uint16_t native_vlan = 1;       // Default VLAN for untagged packets on access/hybrid/trunk
        std::set<uint16_t> allowed_vlans; // For trunk/hybrid ports, specifies allowed VLANs
        bool tag_native = false;        // For trunk/hybrid, whether to tag native VLAN traffic on egress

        PortConfig() {
            // Default ACCESS port allows only its native_vlan implicitly
            if (type == PortType::ACCESS) {
                allowed_vlans.insert(native_vlan);
            }
        }
    };

    explicit VlanManager(const VlanManagerConfig& global_config = VlanManagerConfig());

    void configure_port(uint32_t port_id, const PortConfig& config);

    std::optional<PortConfig> get_port_config(uint32_t port_id) const;

    // Determines if traffic with a given VLAN ID can pass from ingress_port to egress_port.
    bool should_forward(uint32_t ingress_port_id, uint32_t egress_port_id, uint16_t vlan_id) const;

    // Processes a packet arriving on an ingress port.
    // Modifies packet (e.g., adds VLAN tag) and returns an action.
    PacketAction process_ingress(Packet& pkt, uint32_t port_id);

    // Processes a packet leaving on an egress port.
    // Modifies packet (e.g., removes or changes VLAN tag).
    void process_egress(Packet& pkt, uint32_t port_id);

private:
    std::map<uint32_t, PortConfig> port_configs_;
    VlanManagerConfig global_config_;

    // Helper to get internal VLAN id if packet is untagged but associated with native
    // This is a placeholder concept for more complex VLAN processing logic.
    // PacketBuffer could be extended to carry this "implicit" VLAN id.
    // For now, Packet class methods like pkt.vlan_id() handle explicit tags.
    // And process_ingress/egress use port config for implicit native VLAN handling.
};

// Add a placeholder to PacketBuffer for internal VLAN ID tracking if needed by VlanManager
// This is an intrusive change to PacketBuffer, ideally done via a non-intrusive way or dedicated field
// For now, this is a conceptual note.
// In packet_buffer.hpp:
// struct PacketBuffer {
//   ...
//   uint16_t vlan_id_internal_placeholder = 0; // 0 if no vlan or not applicable
//   ...
// };


} // namespace netflow

#endif // NETFLOW_VLAN_MANAGER_HPP
