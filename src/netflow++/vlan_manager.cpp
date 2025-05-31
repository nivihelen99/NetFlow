#include "netflow++/vlan_manager.hpp"
#include <map>       // For std::map
#include <set>       // For std::set
#include <optional>  // For std::optional, std::nullopt
#include <stdexcept> // For std::invalid_argument (though not directly used in moved methods, good for context)

// Packet class is included via vlan_manager.hpp -> packet.hpp

namespace netflow {

VlanManager::VlanManager(const VlanManagerConfig& global_config)
    : global_config_(global_config) {}

void VlanManager::configure_port(uint32_t port_id, const PortConfig& config) {
    PortConfig new_config = config;
    // Ensure basic consistency for access ports
    if (new_config.type == PortType::ACCESS) {
        new_config.allowed_vlans.clear();
        new_config.allowed_vlans.insert(new_config.native_vlan); // Access port implicitly allows only its native VLAN
    }
    port_configs_[port_id] = new_config;
}

std::optional<VlanManager::PortConfig> VlanManager::get_port_config(uint32_t port_id) const {
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second; // Return by value, wrapped in std::optional
    }
    return std::nullopt;
}

// Determines if traffic with a given VLAN ID can pass from ingress_port to egress_port.
bool VlanManager::should_forward(uint32_t ingress_port_id, uint32_t egress_port_id, uint16_t vlan_id) const {
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
PacketAction VlanManager::process_ingress(Packet& pkt, uint32_t port_id) {
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
                // Packet on access port has a VLAN tag
                if (packet_vlan_id != config.native_vlan) {
                    return PacketAction::DROP; // Tagged with wrong VLAN
                }
                // If tagged with native_vlan, it's allowed. No change to packet.
            } else {
                // Packet is untagged, assign native VLAN
                // It will be tagged internally. Egress processing will decide if it's stripped.
                if (!pkt.push_vlan(config.native_vlan, 0)) {
                    // Failed to push VLAN (e.g. buffer full, though push_vlan might not check this robustly yet)
                    return PacketAction::DROP;
                }
            }
            // After processing, packet is considered to be in native_vlan. Check if this VLAN is allowed.
            // This check is somewhat redundant for ACCESS if allowed_vlans is correctly set up by configure_port.
            if (!config.allowed_vlans.count(config.native_vlan)) {
                return PacketAction::DROP; // Native VLAN not in allowed set (misconfiguration)
            }
            break;

        case PortType::TRUNK:
        case PortType::HYBRID: // Simplified HYBRID: acts like TRUNK for ingress VLAN check
            if (packet_has_vlan) {
                // Packet is tagged
                if (config.allowed_vlans.count(packet_vlan_id) == 0) {
                    return PacketAction::DROP; // Tagged VLAN not allowed on this trunk
                }
                // Packet's existing tag is allowed.
            } else {
                // Packet is untagged on a trunk/hybrid port, it's associated with the native VLAN.
                // Check if native VLAN is allowed on this trunk.
                if (config.allowed_vlans.count(config.native_vlan) == 0) {
                     return PacketAction::DROP; // Native VLAN not allowed on this trunk
                }
                // Packet remains untagged for now, but is associated with native_vlan for forwarding decisions.
                // If it needs to be tagged for internal processing or before forwarding to another trunk,
                // that logic could be here (e.g., pkt.push_vlan(config.native_vlan) if internal representation requires it).
                // For this model, we assume the vlan_id for should_forward will be config.native_vlan.
            }
            break;
        default:
            return PacketAction::DROP; // Unknown port type
    }
    return PacketAction::FORWARD;
}

void VlanManager::process_egress(Packet& pkt, uint32_t port_id) {
    std::optional<PortConfig> config_opt = get_port_config(port_id);
    if (!config_opt.has_value()) {
        return; // No configuration for this port, packet passes as is (or could be dropped by policy)
    }
    const PortConfig& config = config_opt.value();

    std::optional<uint16_t> packet_vlan_id_opt = pkt.vlan_id();

    // If packet has no VLAN tag, it might be untagged traffic associated with a native VLAN.
    // However, process_ingress usually ensures packets are tagged internally if they were untagged
    // and associated with a native VLAN on ingress (for ACCESS, or potentially for TRUNK/HYBRID if desired).
    // If an untagged packet reaches here, it implies it's truly untagged or already processed.

    if (!packet_vlan_id_opt.has_value()) {
        // If the packet is untagged, it means it's either:
        // 1. Traffic on its native VLAN that was already untagged by ingress (e.g. trunk to trunk native, not tagged)
        // 2. Traffic that should be on native_vlan of this egress port.
        // Egress processing primarily decides whether to *remove* a tag.
        // If it's untagged and needs to be on native_vlan, it's implicitly correct for ACCESS.
        // For TRUNK, if native is not tagged, it's also fine.
        return;
    }

    uint16_t packet_vlan_id = packet_vlan_id_opt.value();

    switch (config.type) {
        case PortType::ACCESS:
            // For an access port, if the packet's VLAN ID matches the port's native VLAN,
            // the tag should be removed.
            if (packet_vlan_id == config.native_vlan) {
                pkt.pop_vlan();
            } else {
                // Packet is on a VLAN not native to this access port.
                // This situation implies a forwarding error or misconfiguration.
                // The packet should ideally be dropped by should_forward.
                // If it reaches here, dropping it or logging an error might be an option.
                // For now, let it pass if should_forward allowed it (though it shouldn't for different VLAN).
            }
            break;

        case PortType::TRUNK:
        case PortType::HYBRID: // Simplified HYBRID: acts like TRUNK for egress tagging
            // For a trunk port, if the packet's VLAN ID is the native VLAN
            // and the port is configured not to tag native VLAN traffic, remove the tag.
            if (packet_vlan_id == config.native_vlan && !config.tag_native) {
                pkt.pop_vlan();
            }
            // Otherwise (tagged non-native, or native and tag_native is true), the tag remains.
            break;
        default:
            // Unknown port type, do nothing to the packet.
            break;
    }
}

} // namespace netflow
