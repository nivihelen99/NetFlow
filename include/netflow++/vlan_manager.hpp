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

    const PortConfig* get_port_config(uint32_t port_id) const {
        auto it = port_configs_.find(port_id);
        if (it != port_configs_.end()) {
            return &it->second;
        }
        return nullptr; // Or return a default configuration
    }

    // Determines if traffic with a given VLAN ID can pass from ingress_port to egress_port.
    bool should_forward(uint32_t ingress_port_id, uint32_t egress_port_id, uint16_t vlan_id) const {
        const PortConfig* ingress_cfg = get_port_config(ingress_port_id);
        const PortConfig* egress_cfg = get_port_config(egress_port_id);

        if (!ingress_cfg || !egress_cfg) {
            return false; // Port configuration missing
        }

        // Check if VLAN is allowed on ingress port
        bool allowed_on_ingress = false;
        if (ingress_cfg->type == PortType::ACCESS) {
            allowed_on_ingress = (vlan_id == ingress_cfg->native_vlan);
        } else { // TRUNK or HYBRID
            allowed_on_ingress = (ingress_cfg->allowed_vlans.count(vlan_id) > 0);
        }

        if (!allowed_on_ingress) {
            return false;
        }

        // Check if VLAN is allowed on egress port
        bool allowed_on_egress = false;
        if (egress_cfg->type == PortType::ACCESS) {
            allowed_on_egress = (vlan_id == egress_cfg->native_vlan);
        } else { // TRUNK or HYBRID
            allowed_on_egress = (egress_cfg->allowed_vlans.count(vlan_id) > 0);
        }

        return allowed_on_egress;
    }

    // Processes a packet arriving on an ingress port.
    // Modifies packet (e.g., adds VLAN tag) and returns an action.
    PacketAction process_ingress(Packet& pkt, uint32_t port_id) {
        const PortConfig* config = get_port_config(port_id);
        if (!config) {
            return PacketAction::DROP; // No configuration for this port
        }

        bool packet_has_vlan = pkt.has_vlan();
        std::optional<uint16_t> packet_vlan_id_opt = pkt.vlan_id();
        uint16_t packet_vlan_id = packet_vlan_id_opt.value_or(0); // 0 if no VLAN tag

        switch (config->type) {
            case PortType::ACCESS:
                if (packet_has_vlan) {
                    // Access ports typically drop tagged frames, or only accept if tag matches native_vlan.
                    // For simplicity, let's say it drops any tagged frame not matching native_vlan.
                    // A stricter interpretation is access ports only accept untagged frames.
                    if (packet_vlan_id != config->native_vlan) {
                         // Or if any tag is present and not expected (e.g. if native_vlan untagged)
                        return PacketAction::DROP;
                    }
                    // If tagged with native_vlan, it might be accepted or stripped. Let's assume it's accepted as is.
                } else {
                    // Untagged frame received on access port. Tag it with the native VLAN.
                    // This assumes the packet buffer has space for a VLAN tag if one needs to be added.
                    // The Packet::push_vlan method handles this, but might fail if no space.
                    if (!pkt.push_vlan(config->native_vlan, 0)) { // Assuming priority 0
                        return PacketAction::DROP; // Cannot add VLAN tag (e.g. buffer too small)
                    }
                }
                // After processing, the packet is considered to be in its native_vlan.
                // Check if this VLAN (native_vlan) is allowed (implicitly it is for access port's own native vlan)
                if (!config->allowed_vlans.count(config->native_vlan)) { // Should always be true due to configure_port logic
                    return PacketAction::DROP;
                }
                break;

            case PortType::TRUNK:
            case PortType::HYBRID: // Simplified Hybrid: acts like Trunk for tagged, like Access for untagged native
                if (packet_has_vlan) {
                    // Tagged frame on a trunk port. Check if its VLAN is allowed.
                    if (config->allowed_vlans.count(packet_vlan_id) == 0) {
                        return PacketAction::DROP; // VLAN not allowed on this trunk
                    }
                    // Packet proceeds with its existing tag.
                } else {
                    // Untagged frame on a trunk/hybrid port. It's assigned the native VLAN.
                    // It might or might not be tagged based on `tag_native` on egress.
                    // For ingress processing, we consider it as belonging to native_vlan.
                    // If native_vlan is not in allowed_vlans (unusual config), it might be dropped.
                    if (config->allowed_vlans.count(config->native_vlan) == 0) {
                         return PacketAction::DROP; // Native VLAN not allowed on this trunk (misconfiguration)
                    }
                    // If `tag_native` is true OR if it's a hybrid port that should tag it internally:
                    // Conceptually, the packet is now associated with native_vlan.
                    // If it needs to be physically tagged to represent this internally:
                    // pkt.push_vlan(config->native_vlan, 0); // This is if untagged means it *becomes* tagged with native
                    // However, often for trunk ports, untagged ingress is just *associated* with native_vlan,
                    // and tagging decision (if native) happens on egress.
                    // Let's assume it's just associated, and push_vlan isn't strictly needed here
                    // unless the internal representation requires all packets to be tagged.
                    // For now, we'll rely on the egress to handle tagging of native VLAN.
                    // The packet_vlan_id for forwarding decision will be config->native_vlan.
                }
                break;
            default:
                return PacketAction::DROP; // Unknown port type
        }
        return PacketAction::FORWARD;
    }

    // Processes a packet going out on an egress port.
    // Modifies packet (e.g., strips VLAN tag).
    // This function assumes should_forward has already permitted this vlan_id on this egress_port.
    void process_egress(Packet& pkt, uint32_t port_id) {
        const PortConfig* config = get_port_config(port_id);
        if (!config) {
            // Should not happen if should_forward was checked, but as a safeguard:
            // No action or treat as drop (though packet is already past forwarding decision)
            return;
        }

        std::optional<uint16_t> packet_vlan_id_opt = pkt.vlan_id();
        if (!packet_vlan_id_opt.has_value()) { // Packet is untagged
             // If it's untagged, it's implicitly the native VLAN of the ingress path.
             // On egress, if this port is an access port and the vlan matches native, it's fine.
             // If it's a trunk and it's the native vlan, it egresses untagged (unless tag_native is true)
            // The check for vlan_id_internal_placeholder has been removed.
            // This logic needs re-evaluation if untagged native VLAN packets on trunk
            // need explicit tagging on egress when tag_native is true.
            // One way is that process_ingress ensures the packet is tagged with native_vlan
            // if it arrived untagged on a trunk, before it reaches egress processing.
            // if ((config->type == PortType::TRUNK || config->type == PortType::HYBRID) &&
            //     pkt.get_buffer()->vlan_id_internal_placeholder == config->native_vlan &&
            //     config->tag_native) {
                // This case is tricky: untagged packet on ingress was associated with native_vlan.
                // If egress trunk port has tag_native=true for this native_vlan, it must be tagged now.
                // This implies process_ingress should have tagged it, or we tag it here.
                // Let's assume process_ingress sets the packet's effective VLAN ID.
                // If pkt.vlan_id() is null, it implies it's untagged.
                // If this untagged packet corresponds to native_vlan and tag_native is true, tag it.
                // This specific check is removed due to vlan_id_internal_placeholder removal.
                // The broader logic of when to tag untagged native VLAN traffic on egress
                // for a trunk port with tag_native=true needs to be handled, likely by
                // ensuring pkt.has_vlan() is true with the native_vlan if it needs tagging.
                // if (pkt.get_buffer()->vlan_id_internal_placeholder == config->native_vlan && !pkt.has_vlan()){
                //    pkt.push_vlan(config->native_vlan, 0); // Tag it
                // }
            // }
            return; // Untagged packets generally pass as is, or are handled by native VLAN logic
        }

        uint16_t packet_vlan_id = packet_vlan_id_opt.value();

        switch (config->type) {
            case PortType::ACCESS:
                // Packet is tagged. If VLAN ID matches native VLAN, strip the tag.
                // Access ports send out untagged frames for their native VLAN.
                if (packet_vlan_id == config->native_vlan) {
                    if (!pkt.pop_vlan()) {
                        // Log error: Failed to pop VLAN (e.g. buffer issue, though unlikely for pop)
                        // This might indicate a problem, packet could be malformed or drop.
                    }
                } else {
                    // This case should ideally not be reached if should_forward is correct,
                    // as an access port should only egress its native_vlan.
                    // If it does, it's a policy violation - typically drop, but here just no modification.
                }
                break;

            case PortType::TRUNK:
            case PortType::HYBRID:
                // Packet is tagged.
                // If the VLAN ID is the native VLAN for this trunk/hybrid port,
                // and tag_native is false, strip the tag.
                if (packet_vlan_id == config->native_vlan && !config->tag_native) {
                    if (!pkt.pop_vlan()) {
                        // Log error or handle failure to pop.
                    }
                }
                // Otherwise (VLAN is not native, or it is native but tag_native is true),
                // the packet egresses with its existing tag.
                break;
            default:
                // Unknown port type, no action.
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
