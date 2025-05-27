#include "netflow/switch/VlanManager.h"
#include <iostream> // For debug/info messages

VlanManager::VlanManager() {
    // std::cout << "VlanManager initialized." << std::endl;
}

bool VlanManager::configure_port(uint16_t port_id, const PortConfig& config) {
    if (config.type == PortType::ACCESS) {
        if (config.access_vlan_id == 0 || config.access_vlan_id > MAX_VLAN_ID) {
            // std::cerr << "Error: Invalid access_vlan_id " << config.access_vlan_id << " for port " << port_id << std::endl;
            return false;
        }
    } else if (config.type == PortType::TRUNK || config.type == PortType::NATIVE_VLAN) {
        if (config.native_vlan_id == 0 || config.native_vlan_id > MAX_VLAN_ID) {
            // std::cerr << "Error: Invalid native_vlan_id " << config.native_vlan_id << " for port " << port_id << std::endl;
            return false;
        }
        for (uint16_t vlan_id : config.allowed_vlans) {
            if (vlan_id == 0 || vlan_id > MAX_VLAN_ID) {
                // std::cerr << "Error: Invalid allowed_vlan_id " << vlan_id << " in config for port " << port_id << std::endl;
                return false;
            }
        }
    }
    
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    port_configurations_[port_id] = config;
    // std::cout << "VLAN Port " << port_id << " configured. Type: " << static_cast<int>(config.type)
    //           << " Access/Native VLAN: " << (config.type == PortType::ACCESS ? config.access_vlan_id : config.native_vlan_id)
    //           << std::endl;
    return true;
}

const VlanManager::PortConfig* VlanManager::get_port_config(uint16_t port_id) const {
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it != port_configurations_.end()) {
        return &it->second;
    }
    return nullptr;
}

uint16_t VlanManager::process_ingress(Packet& pkt, uint16_t port_id) {
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it == port_configurations_.end()) {
        // std::cerr << "VlanManager Warning: No configuration for ingress port " << port_id << ". Dropping." << std::endl;
        return VLAN_DROP; // No configuration, drop
    }
    const PortConfig& config = it->second;
    bool packet_is_tagged = pkt.has_vlan();
    uint16_t packet_original_vlan_id = 0;
    if (packet_is_tagged) {
        packet_original_vlan_id = pkt.vlan_id();
    }

    switch (config.type) {
        case PortType::ACCESS:
            if (packet_is_tagged) {
                // Access port receiving tagged frame.
                // Standard behavior: drop if tag doesn't match access_vlan_id.
                // Some switches might allow if it matches, some might always drop tagged frames on access ports.
                // Let's assume it's allowed if it matches the access VLAN.
                if (packet_original_vlan_id == config.access_vlan_id) {
                    return config.access_vlan_id; // Already correctly tagged for this access VLAN
                } else {
                    // std::cout << "Ingress Drop: Tagged frame on access port " << port_id 
                    //           << " with mismatched VLAN ID " << packet_original_vlan_id 
                    //           << " (expected " << config.access_vlan_id << ")" << std::endl;
                    return VLAN_DROP; // Tagged with wrong VLAN
                }
            } else {
                // Untagged frame on access port, tag it with the access VLAN ID.
                // The Packet::push_vlan is simplified, assumes TPID 0x8100
                // TCI: Priority can be 0, DEI 0, VID is access_vlan_id
                uint16_t tci = config.access_vlan_id; // PCP=0, DEI=0
                if (!pkt.push_vlan(0x8100, tci)) {
                    // std::cerr << "Ingress Error: Failed to push VLAN tag on port " << port_id << std::endl;
                    return VLAN_DROP; // Failed to add tag
                }
                return config.access_vlan_id;
            }

        case PortType::TRUNK:
            if (packet_is_tagged) {
                if (config.allowed_vlans.empty() || config.allowed_vlans.count(packet_original_vlan_id)) {
                    return packet_original_vlan_id; // Tagged and allowed
                } else {
                    // std::cout << "Ingress Drop: Tagged frame on trunk port " << port_id
                    //           << " with disallowed VLAN ID " << packet_original_vlan_id << std::endl;
                    return VLAN_DROP; // Tagged but not in allowed list
                }
            } else {
                // Untagged on a pure trunk port (no native VLAN behavior specified for PortType::TRUNK)
                // std::cout << "Ingress Drop: Untagged frame on pure trunk port " << port_id << std::endl;
                return VLAN_DROP; 
            }

        case PortType::NATIVE_VLAN: // Trunk port with native VLAN handling
            if (packet_is_tagged) {
                 // If tagged with native VLAN ID, some switches might drop it or strip tag.
                 // Standard behavior: if tagged and allowed, pass it.
                if (packet_original_vlan_id == config.native_vlan_id) {
                     // Cisco drops frames tagged with native VLAN ID by default on trunk.
                     // Others might accept. Let's be strict for now.
                     // std::cout << "Ingress Drop: Frame tagged with native VLAN ID " << packet_original_vlan_id 
                     //           << " on trunk port " << port_id << std::endl;
                     // return VLAN_DROP; 
                     // OR, more commonly, treat it as part of the native VLAN, but it's already tagged.
                     // If it's allowed, it should pass.
                }
                if (config.allowed_vlans.empty() || config.allowed_vlans.count(packet_original_vlan_id)) {
                    return packet_original_vlan_id; // Tagged and allowed
                } else {
                    // std::cout << "Ingress Drop: Tagged frame on trunk port " << port_id
                    //           << " with disallowed VLAN ID " << packet_original_vlan_id << std::endl;
                    return VLAN_DROP; // Tagged but not in allowed list
                }
            } else { // Untagged frame
                // Tag with native VLAN ID.
                uint16_t tci = config.native_vlan_id; // PCP=0, DEI=0
                if (!pkt.push_vlan(0x8100, tci)) {
                    // std::cerr << "Ingress Error: Failed to push native VLAN tag on port " << port_id << std::endl;
                    return VLAN_DROP;
                }
                return config.native_vlan_id;
            }
        default:
            return VLAN_DROP;
    }
}

bool VlanManager::process_egress(Packet& pkt, uint16_t port_id, uint16_t pkt_vlan_id) {
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it == port_configurations_.end()) {
        // std::cerr << "VlanManager Warning: No configuration for egress port " << port_id << ". Dropping." << std::endl;
        return false; // No configuration, drop
    }
    const PortConfig& config = it->second;

    // Ensure packet is tagged correctly internally before egress logic, unless it's already untagged
    // and matches native (this check is more for sanity, ingress should handle tagging)
    bool packet_is_currently_tagged = pkt.has_vlan();
    uint16_t current_tag_vid = 0;
    if (packet_is_currently_tagged) {
        current_tag_vid = pkt.vlan_id();
        if (current_tag_vid != pkt_vlan_id) {
            // This implies a mismatch between FDB/internal VLAN and actual packet tag.
            // This state should ideally not be reached if ingress + FDB is correct.
            // std::cerr << "Egress Warning: Packet VID " << current_tag_vid 
            //           << " mismatches expected internal VID " << pkt_vlan_id << " for port " << port_id << std::endl;
            // Depending on strictness, could drop here. For now, proceed with pkt_vlan_id.
        }
    }


    switch (config.type) {
        case PortType::ACCESS:
            if (pkt_vlan_id == config.access_vlan_id) {
                if (packet_is_currently_tagged) { // Should be tagged with access_vlan_id
                    if (!pkt.pop_vlan()) {
                        // std::cerr << "Egress Error: Failed to pop VLAN tag on access port " << port_id << std::endl;
                        return false; // Failed to remove tag
                    }
                } else {
                    // Packet is untagged but belongs to access_vlan_id. This is okay.
                }
                return true; // Forward untagged
            } else {
                // std::cout << "Egress Drop: Packet VLAN " << pkt_vlan_id 
                //           << " does not match access VLAN " << config.access_vlan_id 
                //           << " on port " << port_id << std::endl;
                return false; // Packet not for this access VLAN
            }

        case PortType::TRUNK:
            // For pure trunk, all egress packets must be tagged and allowed.
            if (!packet_is_currently_tagged && pkt_vlan_id != 0) {
                 // If packet is supposed to have a VLAN ID but isn't tagged, it's an anomaly or needs tagging.
                 // Assuming ingress ensures packets are tagged if they belong to a VLAN.
                 // Let's try to tag it if it's not, using pkt_vlan_id.
                uint16_t tci = pkt_vlan_id; // PCP=0, DEI=0
                if (!pkt.push_vlan(0x8100, tci)) {
                    // std::cerr << "Egress Error: Failed to push VLAN tag on trunk port " << port_id << std::endl;
                    return false;
                }
                packet_is_currently_tagged = true; // Now it's tagged
            }

            if (packet_is_currently_tagged && (config.allowed_vlans.empty() || config.allowed_vlans.count(pkt_vlan_id))) {
                return true; // Forward tagged
            } else {
                // std::cout << "Egress Drop: Packet VLAN " << pkt_vlan_id 
                //           << " not allowed or not tagged on trunk port " << port_id << std::endl;
                return false; // Not allowed or not tagged appropriately
            }

        case PortType::NATIVE_VLAN: // Trunk with native VLAN
            if (pkt_vlan_id == config.native_vlan_id) {
                if (packet_is_currently_tagged) { // If tagged with native VLAN ID, strip tag
                    if (!pkt.pop_vlan()) {
                        // std::cerr << "Egress Error: Failed to pop native VLAN tag on port " << port_id << std::endl;
                        return false;
                    }
                }
                return true; // Forward untagged (as it's native)
            } else { // For other VLANs
                 if (!packet_is_currently_tagged && pkt_vlan_id != 0) { // Should be tagged
                    uint16_t tci = pkt_vlan_id; // PCP=0, DEI=0
                    if (!pkt.push_vlan(0x8100, tci)) {
                        // std::cerr << "Egress Error: Failed to push VLAN tag on trunk port " << port_id << " for VLAN " << pkt_vlan_id << std::endl;
                        return false;
                    }
                     packet_is_currently_tagged = true;
                 }

                if (packet_is_currently_tagged && (config.allowed_vlans.empty() || config.allowed_vlans.count(pkt_vlan_id))) {
                    return true; // Forward tagged
                } else {
                    // std::cout << "Egress Drop: Packet VLAN " << pkt_vlan_id 
                    //           << " not allowed or not tagged on trunk/native port " << port_id << std::endl;
                    return false;
                }
            }
        default:
            return false;
    }
}

bool VlanManager::should_forward(uint16_t port_id, uint16_t pkt_vlan_id) const {
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it == port_configurations_.end()) {
        return false; // No config, don't forward
    }
    const PortConfig& config = it->second;

    switch (config.type) {
        case PortType::ACCESS:
            return pkt_vlan_id == config.access_vlan_id;
        case PortType::TRUNK:
            return config.allowed_vlans.empty() || config.allowed_vlans.count(pkt_vlan_id);
        case PortType::NATIVE_VLAN:
            // Allowed if it's the native VLAN or an explicitly allowed tagged VLAN
            return pkt_vlan_id == config.native_vlan_id || 
                   (config.allowed_vlans.empty() || config.allowed_vlans.count(pkt_vlan_id));
        default:
            return false;
    }
}

bool VlanManager::is_vlan_member(uint16_t port_id, uint16_t vlan_id) const {
    // This is essentially the same logic as should_forward for a given vlan_id
    return should_forward(port_id, vlan_id);
}

bool VlanManager::add_vlan_member(uint16_t port_id, uint16_t vlan_id) {
    if (vlan_id == 0 || vlan_id > MAX_VLAN_ID) return false;

    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it == port_configurations_.end()) {
        // std::cerr << "VlanManager Error: Cannot add VLAN member to unconfigured port " << port_id << std::endl;
        return false; // Port not configured
    }
    PortConfig& config = it->second;
    if (config.type == PortType::TRUNK || config.type == PortType::NATIVE_VLAN) {
        config.allowed_vlans.insert(vlan_id);
        return true;
    }
    // std::cerr << "VlanManager Warning: Cannot add VLAN member to port " << port_id 
    //           << " as it's not a TRUNK or NATIVE_VLAN type." << std::endl;
    return false; // Not a trunk port
}

bool VlanManager::remove_vlan_member(uint16_t port_id, uint16_t vlan_id) {
    std::lock_guard<std::mutex> lock(vlan_mutex_);
    auto it = port_configurations_.find(port_id);
    if (it == port_configurations_.end()) {
        // std::cerr << "VlanManager Error: Cannot remove VLAN member from unconfigured port " << port_id << std::endl;
        return false; // Port not configured
    }
    PortConfig& config = it->second;
    if (config.type == PortType::TRUNK || config.type == PortType::NATIVE_VLAN) {
        config.allowed_vlans.erase(vlan_id);
        return true;
    }
    // std::cerr << "VlanManager Warning: Cannot remove VLAN member from port " << port_id 
    //           << " as it's not a TRUNK or NATIVE_VLAN type." << std::endl;
    return false; // Not a trunk port
}
