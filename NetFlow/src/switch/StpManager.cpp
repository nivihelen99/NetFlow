#include "netflow/switch/StpManager.h"
#include <cstring>   // For memcpy
#include <algorithm> // For std::min, std::max
#include <iostream>  // For debug/info
#include <arpa/inet.h> // For htons, ntohl etc. (BPDU fields are network byte order)

// Helper for htobe64 / be64toh if not available (e.g. on some systems or older glibc)
// This is a common requirement as these functions are not as standard as htonl/s.
#if defined(__APPLE__) || (defined(_WIN32) || defined(_WIN64))
// macOS and Windows have different endian conversion functions or need custom ones.
// For simplicity, assuming a little-endian host system for this fallback.
// A production system would use platform-specific or library functions (like from Boost).
inline uint64_t htobe64(uint64_t host_64) {
    const int num = 1;
    if (*(char *)&num == 1) { // Little-endian
        return (((uint64_t)htonl(static_cast<uint32_t>(host_64 & 0xFFFFFFFFULL))) << 32) | htonl(static_cast<uint32_t>(host_64 >> 32));
    } else { // Big-endian
        return host_64;
    }
}
inline uint64_t be64toh(uint64_t big_endian_64) {
    const int num = 1;
    if (*(char *)&num == 1) { // Little-endian
        return (((uint64_t)ntohl(static_cast<uint32_t>(big_endian_64 & 0xFFFFFFFFULL))) << 32) | ntohl(static_cast<uint32_t>(big_endian_64 >> 32));
    } else { // Big-endian
        return big_endian_64;
    }
}
#elif !defined(be64toh) && defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 9))
// Older glibc might not have be64toh. This is a rough check.
// Custom implementation for little-endian host:
inline uint64_t htobe64(uint64_t host_64) {
    return (((uint64_t)htonl(static_cast<uint32_t>(host_64 & 0xFFFFFFFFULL))) << 32) | htonl(static_cast<uint32_t>(host_64 >> 32));
}
inline uint64_t be64toh(uint64_t big_endian_64) {
     return (((uint64_t)ntohl(static_cast<uint32_t>(big_endian_64 & 0xFFFFFFFFULL))) << 32) | ntohl(static_cast<uint32_t>(big_endian_64 >> 32));
}
// For other systems that might miss it but have __BYTE_ORDER and __LITTLE_ENDIAN/__BIG_ENDIAN
#elif !defined(be64toh) && defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
inline uint64_t htobe64(uint64_t host_64) {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return (((uint64_t)htonl(static_cast<uint32_t>(host_64 & 0xFFFFFFFFULL))) << 32) | htonl(static_cast<uint32_t>(host_64 >> 32));
    #else // __BYTE_ORDER == __BIG_ENDIAN
        return host_64;
    #endif
}
inline uint64_t be64toh(uint64_t big_endian_64) {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return (((uint64_t)ntohl(static_cast<uint32_t>(big_endian_64 & 0xFFFFFFFFULL))) << 32) | ntohl(static_cast<uint32_t>(big_endian_64 >> 32));
    #else // __BYTE_ORDER == __BIG_ENDIAN
        return big_endian_64;
    #endif
}
#endif


// Helper to combine priority and MAC for BridgeId
BridgeId make_bridge_id(uint32_t priority, const MACAddress& mac) {
    return (static_cast<uint64_t>(priority & 0xFFFF) << 48) |
           (static_cast<uint64_t>(mac[0]) << 40) |
           (static_cast<uint64_t>(mac[1]) << 32) |
           (static_cast<uint64_t>(mac[2]) << 24) |
           (static_cast<uint64_t>(mac[3]) << 16) |
           (static_cast<uint64_t>(mac[4]) << 8)  |
           static_cast<uint64_t>(mac[5]);
}


StpManager::StpManager() {
    // Default bridge config (e.g. highest priority initially)
    bridge_config_.bridge_priority = 0x8000; // Default STP priority
    // MAC needs to be set from somewhere (e.g. system or config file)
    // For now, use a placeholder MAC.
    MACAddress default_mac = {0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC};
    bridge_config_.bridge_mac = default_mac;
    bridge_config_.bridge_id = make_bridge_id(bridge_config_.bridge_priority, bridge_config_.bridge_mac);
    
    current_root_bridge_id_ = bridge_config_.bridge_id; // Assume self is root initially
    current_root_path_cost_ = 0;
    root_port_id_ = 0; // No root port if self is root
    last_bpdu_sent_time_ = std::chrono::steady_clock::now();

    // std::cout << "StpManager initialized. Bridge ID: " << std::hex << bridge_config_.bridge_id << std::dec << std::endl;
}

void StpManager::set_bridge_config(const BridgeConfig& config) {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    bridge_config_ = config;
    // Re-evaluate if we are root if bridge ID changes
    // This is a simplified update; a real change might require full STP re-convergence.
    elect_root_port();
    determine_designated_ports();
    for(auto& entry : port_stp_info_) {
        update_port_role(entry.first);
    }
    // std::cout << "StpManager Bridge config updated. New Bridge ID: " << std::hex << bridge_config_.bridge_id << std::dec << std::endl;
}

const BridgeConfig& StpManager::get_bridge_config() const {
    // std::lock_guard<std::mutex> lock(stp_mutex_); // Not strictly needed for const ref to immutable parts if not modified.
    return bridge_config_;
}

bool StpManager::configure_port(PortId port_id, uint32_t path_cost, bool stp_enabled) {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto& p_info = port_stp_info_[port_id];
    p_info.port_id = port_id;
    p_info.path_cost = path_cost;

    if (!stp_enabled) {
        p_info.state = StpPortState::DISABLED; 
        p_info.is_designated_port = false;
        p_info.is_root_port = false;
    } else {
        // If STP is being enabled (or was enabled), default to BLOCKING
        p_info.state = StpPortState::BLOCKING;
        // Initialize BPDU info for this port assuming we are the designated bridge for it initially
        // or that it hasn't heard anything better.
        p_info.designated_root_bridge_id = current_root_bridge_id_; // Our current view of root
        p_info.designated_root_path_cost = current_root_path_cost_; // Our current cost to root
        p_info.designated_bridge_id = bridge_config_.bridge_id;    // We are the sender
        p_info.designated_port_id_on_designated_bridge = port_id;  // Our port ID
        p_info.is_designated_port = true; // Assume designated until challenged
        p_info.is_root_port = false;
        p_info.last_bpdu_received_time = std::chrono::steady_clock::time_point(); // Reset
    }
    
    // After configuring a port, re-evaluate roles
    elect_root_port();
    determine_designated_ports();
    // Update all port roles as adding/changing one port can affect others
    for(auto& entry : port_stp_info_) {
        update_port_role(entry.first);
    }

    // std::cout << "STP Port " << port_id << " configured. Path Cost: " << path_cost 
    //           << " STP Enabled: " << stp_enabled << " Initial State: " << static_cast<int>(p_info.state) << std::endl;
    return true;
}

bool StpManager::set_port_state(PortId port_id, StpPortState new_state) {
    // This function is more of an internal helper now (transition_port_state)
    // External calls should use configure_port or rely on STP logic.
    // For direct override (e.g. admin down):
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto it = port_stp_info_.find(port_id);
    if (it != port_stp_info_.end()) {
        if (new_state == StpPortState::DISABLED) {
            it->second.state = StpPortState::DISABLED;
            it->second.is_root_port = false;
            it->second.is_designated_port = false;
            // std::cout << "STP Port " << port_id << " administratively DISABLED." << std::endl;
            // Re-evaluate STP roles for other ports
            elect_root_port();
            determine_designated_ports();
            for(auto& entry : port_stp_info_) {
                if(entry.first != port_id) update_port_role(entry.first);
            }
            return true;
        }
        // For other states, prefer transition_port_state to manage timers.
        // std::cout << "STP Port " << port_id << " direct state set to " << static_cast<int>(new_state) << ". Use configure_port or STP logic." << std::endl;
        // it->second.state = new_state; // Avoid direct set for states other than DISABLED from here
        return false; 
    }
    return false;
}

StpPortState StpManager::get_port_state(PortId port_id) const {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto it = port_stp_info_.find(port_id);
    if (it != port_stp_info_.end()) {
        return it->second.state;
    }
    return StpPortState::BROKEN; 
}

const PortStpInfo* StpManager::get_port_stp_info(PortId port_id) const {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto it = port_stp_info_.find(port_id);
    if (it != port_stp_info_.end()) {
        return &it->second;
    }
    return nullptr;
}


bool StpManager::should_forward(PortId port_id) const {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto it = port_stp_info_.find(port_id);
    if (it != port_stp_info_.end()) {
        return it->second.state == StpPortState::FORWARDING;
    }
    return false; 
}

// Simplified BPDU parsing
bool parse_simple_bpdu(const unsigned char* data, size_t len, SimpleBpdu& bpdu) {
    if (len < sizeof(SimpleBpdu)) return false; 
    std::memcpy(&bpdu, data, sizeof(SimpleBpdu));
    bpdu.protocol_id = ntohs(bpdu.protocol_id);
    bpdu.root_bridge_id = be64toh(bpdu.root_bridge_id); 
    bpdu.root_path_cost = ntohl(bpdu.root_path_cost);
    bpdu.designated_bridge_id = be64toh(bpdu.designated_bridge_id);
    bpdu.designated_port_id = ntohs(bpdu.designated_port_id);
    bpdu.message_age = ntohs(bpdu.message_age);
    bpdu.max_age = ntohs(bpdu.max_age); // These are already in BPDU time (1/256s)
    bpdu.hello_time = ntohs(bpdu.hello_time); // Same
    bpdu.forward_delay = ntohs(bpdu.forward_delay); // Same
    return true;
}


void StpManager::process_bpdu(const unsigned char* bpdu_data, size_t len, PortId ingress_port) {
    SimpleBpdu received_bpdu;
    if (!parse_simple_bpdu(bpdu_data, len, received_bpdu)) {
        // std::cerr << "STP: Failed to parse BPDU on port " << ingress_port << std::endl;
        return;
    }

    if (received_bpdu.protocol_id != 0x0000 || received_bpdu.version_id != 0x00 || received_bpdu.bpdu_type != 0x00) {
        // std::cerr << "STP: Non-STP Configuration BPDU received on port " << ingress_port << ", ignoring." << std::endl;
        return;
    }
    
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto it = port_stp_info_.find(ingress_port);
    if (it == port_stp_info_.end() || it->second.state == StpPortState::DISABLED) {
        return; 
    }
    PortStpInfo& p_info = it->second;

    if (received_bpdu.designated_bridge_id == bridge_config_.bridge_id) {
        // std::cout << "STP: Received our own BPDU on port " << ingress_port << ". Ignoring." << std::endl;
        return; // Ignore our own BPDUs if looped back
    }
    
    p_info.last_bpdu_received_time = std::chrono::steady_clock::now();
    
    // Store the received BPDU's view of the designated sender for this segment
    p_info.designated_root_bridge_id = received_bpdu.root_bridge_id;
    p_info.designated_root_path_cost = received_bpdu.root_path_cost;
    p_info.designated_bridge_id = received_bpdu.designated_bridge_id;
    p_info.designated_port_id_on_designated_bridge = received_bpdu.designated_port_id;

    // Re-evaluate root port and designated ports based on new information
    elect_root_port(); 
    determine_designated_ports();

    // Update roles for all ports as new BPDU might change entire topology view
    for(auto& entry : port_stp_info_) {
        update_port_role(entry.first);
    }
}

SimpleBpdu StpManager::create_bpdu_from_port_info(PortId port_id) const {
    // Assumes lock is held by caller or data is consistent
    SimpleBpdu bpdu;
    
    bpdu.protocol_id = 0x0000;
    bpdu.version_id = 0x00;
    bpdu.bpdu_type = 0x00; 
    bpdu.flags = 0; 

    bpdu.root_bridge_id = current_root_bridge_id_;
    bpdu.root_path_cost = current_root_path_cost_;
    bpdu.designated_bridge_id = bridge_config_.bridge_id;
    bpdu.designated_port_id = port_id; 

    // Message age for BPDUs originated by this bridge should be 0 if we are root,
    // or based on received BPDU's message age + increment if relaying.
    // This is simplified: if we are not root, we'd take root port's BPDU message_age + some increment.
    // For now, assume 0 for simplicity if we are designated for this port.
    bpdu.message_age = 0; 
    if (current_root_bridge_id_ != bridge_config_.bridge_id && root_port_id_ != 0) {
        // A more accurate message age would come from the BPDU on our root port.
        // For now, keeping it simple.
        // const PortStpInfo& rp_info = port_stp_info_.at(root_port_id_);
        // bpdu.message_age = bpdu_time_to_seconds(rp_info.message_age_from_bpdu_on_root_port) + 1; // Simplified
    }


    bpdu.max_age = bridge_config_.max_age_sec; 
    bpdu.hello_time = bridge_config_.hello_time_sec;
    bpdu.forward_delay = bridge_config_.forward_delay_sec;
    
    return bpdu;
}

std::vector<unsigned char> serialize_simple_bpdu(const SimpleBpdu& bpdu_host) {
    SimpleBpdu bpdu_net = bpdu_host; 

    bpdu_net.protocol_id = htons(bpdu_host.protocol_id);
    bpdu_net.root_bridge_id = htobe64(bpdu_host.root_bridge_id);
    bpdu_net.root_path_cost = htonl(bpdu_host.root_path_cost);
    bpdu_net.designated_bridge_id = htobe64(bpdu_host.designated_bridge_id);
    bpdu_net.designated_port_id = htons(bpdu_host.designated_port_id);
    bpdu_net.message_age = htons(bpdu_host.message_age); 
    bpdu_net.max_age = StpManager::seconds_to_bpdu_time(bpdu_host.max_age); 
    bpdu_net.hello_time = StpManager::seconds_to_bpdu_time(bpdu_host.hello_time);
    bpdu_net.forward_delay = StpManager::seconds_to_bpdu_time(bpdu_host.forward_delay);

    std::vector<unsigned char> buffer(sizeof(SimpleBpdu));
    std::memcpy(buffer.data(), &bpdu_net, sizeof(SimpleBpdu));
    return buffer;
}


std::vector<unsigned char> StpManager::generate_bpdu(PortId port_id) {
    std::lock_guard<std::mutex> lock(stp_mutex_); 
    
    auto it = port_stp_info_.find(port_id);
    if (it == port_stp_info_.end() || !it->second.is_designated_port || it->second.state == StpPortState::DISABLED) {
        return {}; 
    }
    SimpleBpdu bpdu_to_send = create_bpdu_from_port_info(port_id); 
    return serialize_simple_bpdu(bpdu_to_send);
}


void StpManager::run_stp_iteration() {
    std::lock_guard<std::mutex> lock(stp_mutex_);
    auto now = std::chrono::steady_clock::now();

    // Re-evaluate roles first based on current info (e.g. if a port was manually disabled/enabled)
    elect_root_port();
    determine_designated_ports();
    for(auto& entry : port_stp_info_) {
        update_port_role(entry.first);
    }

    for (auto& pair_ : port_stp_info_) {
        PortId port_id = pair_.first;
        PortStpInfo& p_info = pair_.second;

        if (p_info.state == StpPortState::DISABLED) continue;

        // State transition timers
        if (p_info.state == StpPortState::LISTENING || p_info.state == StpPortState::LEARNING) {
            if (now >= p_info.state_timer_expires) {
                if (p_info.state == StpPortState::LISTENING) {
                    transition_port_state(port_id, StpPortState::LEARNING);
                } else { 
                    transition_port_state(port_id, StpPortState::FORWARDING);
                }
            }
        }
        
        // BPDU Max Age timer for information received on a port
        // Only relevant if the port is a root port or a blocking (alternate) port.
        // Designated ports send BPDUs, they don't age out info they send.
        if (p_info.is_root_port || (!p_info.is_designated_port && p_info.state == StpPortState::BLOCKING)) {
            if (p_info.last_bpdu_received_time.time_since_epoch().count() > 0) { // If BPDU ever received
                if (std::chrono::duration_cast<std::chrono::seconds>(now - p_info.last_bpdu_received_time).count() > 
                    bpdu_time_to_seconds(StpManager::seconds_to_bpdu_time(bridge_config_.max_age_sec))) { // Compare seconds
                    // std::cout << "STP: Port " << port_id << " MaxAge timer expired for received BPDU." << std::endl;
                    // Information is stale. Reset this port's view of the designated sender.
                    p_info.designated_root_bridge_id = bridge_config_.bridge_id; // Treat as if it only hears itself or worse
                    p_info.designated_root_path_cost = 0; // Cost to self is 0
                    p_info.designated_bridge_id = bridge_config_.bridge_id;
                    p_info.designated_port_id_on_designated_bridge = port_id;
                    p_info.last_bpdu_received_time = std::chrono::steady_clock::time_point(); // Mark as no valid BPDU

                    // Re-run elections and update roles
                    elect_root_port();
                    determine_designated_ports();
                    for(auto& entry : port_stp_info_) {
                        update_port_role(entry.first);
                    }
                }
            } else if (p_info.is_root_port) {
                 // Root port with no last_bpdu_received_time means something is wrong, or we are root and this is port 0
                 // If we are not root, and root port has no BPDU, it's an issue. Re-elect.
                if(current_root_bridge_id_ != bridge_config_.bridge_id){
                    // std::cout << "STP: Root port " << port_id << " has no BPDU info. Re-evaluating." << std::endl;
                    elect_root_port();
                    determine_designated_ports();
                    for(auto& entry : port_stp_info_) {
                        update_port_role(entry.first);
                    }
                }
            }
        }
    }

    // Send BPDUs on designated ports if hello_time has passed
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_bpdu_sent_time_) >= std::chrono::seconds(bridge_config_.hello_time_sec)) {
        bool am_i_root = (current_root_bridge_id_ == bridge_config_.bridge_id);
        for (const auto& pair_ : port_stp_info_) {
            if (pair_.second.is_designated_port && (pair_.second.state != StpPortState::DISABLED) ) {
                // std::vector<unsigned char> bpdu_bytes = generate_bpdu(pair_.first); // generate_bpdu is private and locks
                // if (!bpdu_bytes.empty()) {
                //     // platform_send_bpdu(pair_.first, bpdu_bytes.data(), bpdu_bytes.size());
                //     // std::cout << "STP: Would send BPDU on port " << pair_.first << std::endl;
                // }
            }
        }
        last_bpdu_sent_time_ = now;
    }
}


void StpManager::update_port_role(PortId port_id) {
    auto it_p_info = port_stp_info_.find(port_id);
    if (it_p_info == port_stp_info_.end() || it_p_info->second.state == StpPortState::DISABLED) {
        return;
    }
    PortStpInfo& p_info = it_p_info->second;

    StpPortState old_state = p_info.state;
    bool old_is_root = p_info.is_root_port;
    bool old_is_designated = p_info.is_designated_port;

    if (port_id == root_port_id_ && current_root_bridge_id_ != bridge_config_.bridge_id) { 
        p_info.is_root_port = true;
        p_info.is_designated_port = false;
        if (old_state == StpPortState::BLOCKING) {
            transition_port_state(port_id, StpPortState::LISTENING);
        }
    } else { 
        p_info.is_root_port = false;
        if (p_info.is_designated_port) { // Must have been set by determine_designated_ports()
            if (old_state == StpPortState::BLOCKING) {
                 transition_port_state(port_id, StpPortState::LISTENING);
            }
        } else { // Not root, not designated -> Alternate/Blocking
            if (old_state != StpPortState::BLOCKING) {
                 transition_port_state(port_id, StpPortState::BLOCKING);
            }
        }
    }
    // If role changed from/to forwarding, TCN logic would be here.
    // if ((old_state == StpPortState::FORWARDING && p_info.state != StpPortState::FORWARDING) ||
    //     (old_state != StpPortState::FORWARDING && p_info.state == StpPortState::FORWARDING)) {
    //     // Trigger TCN
    // }
}


void StpManager::elect_root_port() {
    BridgeId new_current_root_id = bridge_config_.bridge_id; 
    uint32_t new_root_path_cost = 0;
    PortId new_root_port = 0; 
    BridgeId best_designated_bridge_for_root_path = bridge_config_.bridge_id; 
    PortId best_designated_port_for_root_path = 0; 

    for (auto const& [port_id, p_info] : port_stp_info_) {
        if (p_info.state == StpPortState::DISABLED || p_info.designated_bridge_id == 0) continue; // Skip disabled or no BPDU info

        BridgeId bpdu_root_id = p_info.designated_root_bridge_id;
        uint32_t bpdu_sender_cost_to_root = p_info.designated_root_path_cost;
        BridgeId bpdu_sender_bridge_id = p_info.designated_bridge_id;
        PortId bpdu_sender_port_id = p_info.designated_port_id_on_designated_bridge;
        
        uint32_t total_cost_to_bpdu_root_via_this_port = bpdu_sender_cost_to_root + p_info.path_cost;

        bool update_root = false;
        if (bpdu_root_id < new_current_root_id) {
            update_root = true;
        } else if (bpdu_root_id == new_current_root_id) {
            if (total_cost_to_bpdu_root_via_this_port < new_root_path_cost) {
                update_root = true;
            } else if (total_cost_to_bpdu_root_via_this_port == new_root_path_cost) {
                if (bpdu_sender_bridge_id < best_designated_bridge_for_root_path) {
                    update_root = true;
                } else if (bpdu_sender_bridge_id == best_designated_bridge_for_root_path) {
                    if (bpdu_sender_port_id < best_designated_port_for_root_path) {
                        update_root = true;
                    }
                }
            }
        }

        if (update_root) {
            new_current_root_id = bpdu_root_id;
            new_root_path_cost = total_cost_to_bpdu_root_via_this_port;
            new_root_port = port_id;
            best_designated_bridge_for_root_path = bpdu_sender_bridge_id;
            best_designated_port_for_root_path = bpdu_sender_port_id;
        }
    }
    
    current_root_bridge_id_ = new_current_root_id;
    current_root_path_cost_ = new_root_path_cost;
    root_port_id_ = new_root_port;
}

void StpManager::determine_designated_ports() {
    for (auto& pair_ : port_stp_info_) {
        PortId port_id = pair_.first;
        PortStpInfo& p_info = pair_.second;

        if (p_info.state == StpPortState::DISABLED || port_id == root_port_id_) {
            p_info.is_designated_port = false;
            continue;
        }

        if (current_root_bridge_id_ == bridge_config_.bridge_id) { 
            p_info.is_designated_port = true;
        } else {
            // Compare BPDU we would send vs BPDU received on this port (p_info.designated_*)
            bool we_are_better_designated = false;
            // Our offer to be designated for the segment attached to port_id:
            // Root: current_root_bridge_id_
            // Cost: current_root_path_cost_
            // Bridge: bridge_config_.bridge_id
            // Port: port_id (our port that would be designated for the segment)

            // Their offer (from BPDU received on p_info):
            // Root: p_info.designated_root_bridge_id
            // Cost: p_info.designated_root_path_cost
            // Bridge: p_info.designated_bridge_id
            // Port: p_info.designated_port_id_on_designated_bridge
            
            if (current_root_bridge_id_ < p_info.designated_root_bridge_id) we_are_better_designated = true;
            else if (current_root_bridge_id_ == p_info.designated_root_bridge_id) {
                if (current_root_path_cost_ < p_info.designated_root_path_cost) we_are_better_designated = true;
                else if (current_root_path_cost_ == p_info.designated_root_path_cost) {
                    if (bridge_config_.bridge_id < p_info.designated_bridge_id) we_are_better_designated = true;
                    else if (bridge_config_.bridge_id == p_info.designated_bridge_id) {
                        // If all else is equal, our port ID must be lower or equal to be designated for the segment
                        // This means our port ID (port_id) compared to their port ID (p_info.designated_port_id_on_designated_bridge)
                        // This specific tie-breaker implies that the port on the segment with the lower port ID wins if attached to same bridge.
                        // However, the standard is usually that the bridge with the lower bridge ID is designated.
                        // If bridge IDs are equal (which shouldn't happen for different bridges), then port ID.
                        // The comparison here is whether our *offer* is better than *their offer* for the segment.
                        // So, it's our (BridgeId, PortId) vs their (BridgeId, PortId) as the designated entity.
                        if (port_id <= p_info.designated_port_id_on_designated_bridge) { // Our port ID to identify the segment.
                             we_are_better_designated = true;
                        }
                    }
                }
            }
            p_info.is_designated_port = we_are_better_designated;
        }
    }
}


void StpManager::transition_port_state(PortId port_id, StpPortState target_state) {
    auto it = port_stp_info_.find(port_id);
    if (it != port_stp_info_.end()) {
        StpPortState old_state = it->second.state;
        // Allow re-triggering Listening/Learning to reset timers, but for others, avoid no-op.
        if (old_state == target_state && target_state != StpPortState::LISTENING && target_state != StpPortState::LEARNING) {
             return;
        }
        
        it->second.state = target_state;
        it->second.state_timer_expires = std::chrono::steady_clock::now(); 
        
        if (target_state == StpPortState::LISTENING || target_state == StpPortState::LEARNING) {
            it->second.state_timer_expires += std::chrono::seconds(bridge_config_.forward_delay_sec);
        }
        // if (old_state == StpPortState::FORWARDING && target_state != StpPortState::FORWARDING ||
        //     old_state != StpPortState::FORWARDING && target_state == StpPortState::FORWARDING) {
        //     // std::cout << "STP: Port " << port_id << " TCN condition met. Old: " << (int)old_state << " New: " << (int)target_state << std::endl;
        //     // Trigger TCN logic
        // }
    }
}
