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

    VlanManager(const VlanManagerConfig& global_config = VlanManagerConfig())
        : global_config_(global_config) {}

    void configure_port(uint32_t port_id, const PortConfig& config) {
        PortConfig new_config = config;
        // Ensure basic consistency for access ports
        if (new_config.type == PortType::ACCESS) {
            new_config.allowed_vlans.clear();
            new_config.allowed_vlans.insert(new_config.native_vlan); // Access port implicitly allows only its native VLAN
        }
        port_configs_[port_id] = new_config;
    }

    std::optional<PortConfig> get_port_config(uint32_t port_id) const {
        auto it = port_configs_.find(port_id);
        if (it != port_configs_.end()) {
            return it->second; // Return by value, wrapped in std::optional
        }
        return std::nullopt;
    }

    // Determines if traffic with a given VLAN ID can pass from ingress_port to egress_port.
    bool should_forward(uint32_t ingress_port_id, uint32_t egress_port_id, uint16_t vlan_id) const {
        std::optional<PortConfig> ingress_cfg_opt = get_port_config(ingress_port_id);
        std::optional<PortConfig> egress_cfg_opt = get_port_config(egress_port_id);

        if (!ingress_cfg_opt.has_value() || !egress_cfg_opt.has_value()) {
            return false; // Port configuration missing
        }
        const PortConfig& ingress_cfg = ingress_cfg_opt.value();
        const PortConfig& egress_cfg = egress_cfg_opt.value();

        // Check if VLAN is allowed on ingress port
        bool allowed_on_ingress = false;
        if (ingress_cfg.type == PortType::ACCESS) {
            allowed_on_ingress = (vlan_id == ingress_cfg.native_vlan);
        } else { // TRUNK or HYBRID
            allowed_on_ingress = (ingress_cfg.allowed_vlans.count(vlan_id) > 0);
        }

        if (!allowed_on_ingress) {
            return false;
        }

        // Check if VLAN is allowed on egress port
        bool allowed_on_egress = false;
        if (egress_cfg.type == PortType::ACCESS) {
            allowed_on_egress = (vlan_id == egress_cfg.native_vlan);
        } else { // TRUNK or HYBRID
            allowed_on_egress = (egress_cfg.allowed_vlans.count(vlan_id) > 0);
        }

        return allowed_on_egress;
    }

    // Processes a packet arriving on an ingress port.
    // Modifies packet (e.g., adds VLAN tag) and returns an action.
    PacketAction process_ingress(Packet& pkt, uint32_t port_id) {
        std::optional<PortConfig> config_opt = get_port_config(port_id);
        if (!config_opt.has_value()) {
            return PacketAction::DROP; // No configuration for this port
        }
        const PortConfig& config = config_opt.value();

        bool packet_has_vlan = pkt.has_vlan();
        std::optional<uint16_t> packet_vlan_id_opt = pkt.vlan_id();
        uint16_t packet_vlan_id = packet_vlan_id_opt.value_or(0); // 0 if no VLAN tag

        switch (config.type) {
            case PortType::ACCESS:
                if (packet_has_vlan) {
                    if (packet_vlan_id != config.native_vlan) {
                        return PacketAction::DROP;
                    }
                } else {
                    if (!pkt.push_vlan(config.native_vlan, 0)) {
                        return PacketAction::DROP;
                    }
                }
                if (!config.allowed_vlans.count(config.native_vlan)) {
                    return PacketAction::DROP;
                }
                break;

            case PortType::TRUNK:
            case PortType::HYBRID:
                if (packet_has_vlan) {
                    if (config.allowed_vlans.count(packet_vlan_id) == 0) {
                        return PacketAction::DROP;
                    }
                } else {
                    if (config.allowed_vlans.count(config.native_vlan) == 0) {
                         return PacketAction::DROP;
                    }
                }
                break;
            default:
                return PacketAction::DROP;
        }
        return PacketAction::FORWARD;
    }

    void process_egress(Packet& pkt, uint32_t port_id) {
        std::optional<PortConfig> config_opt = get_port_config(port_id);
        if (!config_opt.has_value()) {
            return;
        }
        const PortConfig& config = config_opt.value();

        std::optional<uint16_t> packet_vlan_id_opt = pkt.vlan_id();
        if (!packet_vlan_id_opt.has_value()) {
            return;
        }

        uint16_t packet_vlan_id = packet_vlan_id_opt.value();

        switch (config.type) {
            case PortType::ACCESS:
                if (packet_vlan_id == config.native_vlan) {
                    pkt.pop_vlan(); // Assuming pop_vlan() returns bool, but not checking here for simplicity
                }
                break;

            case PortType::TRUNK:
            case PortType::HYBRID:
                if (packet_vlan_id == config.native_vlan && !config.tag_native) {
                    pkt.pop_vlan(); // Assuming pop_vlan() returns bool
                }
                break;
            default:
                break;
        }
    }

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
