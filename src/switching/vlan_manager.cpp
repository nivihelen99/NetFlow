#include "netflow_plus_plus/switching/vlan_manager.hpp"
#include "netflow_plus_plus/core/packet.hpp" // Required for process_ingress/egress_packet signatures
#include <iostream> // For placeholder messages

namespace netflow_plus_plus {
namespace switching {

VlanManager::VlanManager() {
    // By default, VLAN 1 is often considered created.
    // configured_vlans_.insert(1);
}

void VlanManager::create_vlan(uint16_t vlan_id) {
    if (vlan_id == 0 || vlan_id > 4094) { // VLAN 0 is reserved, 4095 is also reserved.
        // Or throw an exception: throw std::out_of_range("VLAN ID out of range (1-4094)");
        std::cerr << "Error: VLAN ID " << vlan_id << " is out of valid range (1-4094)." << std::endl;
        return;
    }
    configured_vlans_.insert(vlan_id);
}

void VlanManager::delete_vlan(uint16_t vlan_id) {
    configured_vlans_.erase(vlan_id);
    // Also, update all port configurations that might reference this VLAN
    for (auto& pair : port_vlan_configs_) {
        VlanPortConfig& port_config = pair.second;
        if (port_config.native_vlan == vlan_id) {
            // If native VLAN is deleted, reset to default (e.g., 1) or handle as an error/warning
            // For simplicity, let's just remove it from allowed list if it was there due to native.
            // A more robust handling would be needed, e.g. disallowing deletion of native vlan if port is in use.
            if (port_config.mode == PortMode::ACCESS) {
                 // Or set port to a "disabled" or "unconfigured" state.
                 // For now, just removing from allowed if it was the native for access.
                port_config.allowed_vlans.erase(vlan_id);
            }
             // If it was a native VLAN on a trunk, it's just removed from allowed_vlans list.
        }
        port_config.allowed_vlans.erase(vlan_id);
    }
}

bool VlanManager::is_vlan_created(uint16_t vlan_id) const {
    return configured_vlans_.count(vlan_id);
}

std::set<uint16_t> VlanManager::get_configured_vlans() const {
    return configured_vlans_;
}

void VlanManager::configure_port(uint32_t port, const VlanPortConfig& config) {
    VlanPortConfig new_config = config; // Make a copy to modify allowed_vlans if needed
    if (new_config.mode == PortMode::ACCESS) {
        new_config.allowed_vlans.clear(); // Access mode only carries one VLAN (the native/PVID)
        if (is_vlan_created(new_config.native_vlan)) {
             new_config.allowed_vlans.insert(new_config.native_vlan);
        } else {
            // Handle case where native VLAN for access port is not yet created
            std::cerr << "Warning: Configuring port " << port << " in access mode for VLAN "
                      << new_config.native_vlan << ", but VLAN is not created." << std::endl;
            // Optionally, auto-create it: create_vlan(new_config.native_vlan);
            // new_config.allowed_vlans.insert(new_config.native_vlan);
        }
    } else { // TRUNK or HYBRID
        // Ensure all allowed VLANs are actually created
        std::set<uint16_t> validated_allowed_vlans;
        for (uint16_t vlan_id : new_config.allowed_vlans) {
            if (is_vlan_created(vlan_id)) {
                validated_allowed_vlans.insert(vlan_id);
            } else {
                 std::cerr << "Warning: VLAN " << vlan_id << " in allowed list for port " << port
                           << " is not created. It will be ignored." << std::endl;
            }
        }
        new_config.allowed_vlans = validated_allowed_vlans;
        // For trunk, ensure native_vlan is also in allowed_vlans if it's expected to carry it.
        // The 'tag_native_traffic' flag controls if it's tagged or untagged.
        if (is_vlan_created(new_config.native_vlan)) {
             // Typically, native VLAN is implicitly allowed on a trunk.
             // If it's not tagged, it's the PVID for untagged traffic.
             // If it's tagged, it's just another allowed VLAN.
            new_config.allowed_vlans.insert(new_config.native_vlan);
        }
    }
    port_vlan_configs_[port] = new_config;
}

VlanPortConfig VlanManager::get_port_vlan_config(uint32_t port) const {
    auto it = port_vlan_configs_.find(port);
    if (it != port_vlan_configs_.end()) {
        return it->second;
    }
    return VlanPortConfig{}; // Return default config if port not found
}

bool VlanManager::should_forward(uint32_t ingress_port, uint32_t egress_port, uint16_t vlan_id) {
    // Placeholder implementation.
    // A real implementation needs to check:
    // 1. Is vlan_id created?
    // 2. Is ingress_port part of vlan_id (allowed)?
    // 3. Is egress_port part of vlan_id (allowed)?
    // 4. Spanning Tree Protocol (STP) state for the VLAN on these ports.
    // 5. Other L2 security features (port security, ACLs on VLANs).
    if (!is_vlan_created(vlan_id)) return false;

    VlanPortConfig ingress_cfg = get_port_vlan_config(ingress_port);
    VlanPortConfig egress_cfg = get_port_vlan_config(egress_port);

    bool ingress_allows = ingress_cfg.allowed_vlans.count(vlan_id);
    bool egress_allows = egress_cfg.allowed_vlans.count(vlan_id);
    
    // Simplified: if both ports allow the VLAN and the VLAN exists.
    // std::cout << "should_forward check: vlan " << vlan_id
    //           << " ingress (" << ingress_port << ") allows: " << ingress_allows
    //           << " egress (" << egress_port << ") allows: " << egress_allows
    //           << std::endl;
    return ingress_allows && egress_allows;
}

void VlanManager::process_ingress_packet(core::Packet& pkt, uint32_t port) {
    // Placeholder:
    // std::cout << "VlanManager: process_ingress_packet for port " << port << std::endl;
    // - If port is ACCESS:
    //   - If packet is untagged, tag it with port's native_vlan (PVID).
    //   - If packet is tagged and tag == PVID, allow.
    //   - If packet is tagged and tag != PVID, drop (or handle as violation).
    // - If port is TRUNK:
    //   - If packet is untagged, assign to native_vlan. Forward if native_vlan is allowed.
    //   - If packet is tagged:
    //     - If tag is in allowed_vlans, allow.
    //     - Else, drop.
    // This is where pkt.push_vlan() might be used.
}

void VlanManager::process_egress_packet(core::Packet& pkt, uint32_t port) {
    // Placeholder:
    // std::cout << "VlanManager: process_egress_packet for port " << port << std::endl;
    // - If port is ACCESS:
    //   - If packet's VLAN tag == PVID, strip tag (unless specific config says otherwise).
    //   - If packet's VLAN tag != PVID, generally should not happen if ingress logic is correct. Drop.
    // - If port is TRUNK:
    //   - If packet's VLAN tag == native_vlan AND native_vlan is not set to be tagged (tag_native_traffic=false), strip tag.
    //   - Else (packet's VLAN is not native OR native is tagged), keep tag.
    //   - Ensure packet's VLAN is in allowed_vlans (usually checked before deciding to egress here).
    // This is where pkt.pop_vlan() might be used.
}

} // namespace switching
} // namespace netflow_plus_plus
