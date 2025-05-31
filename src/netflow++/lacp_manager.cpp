#include "netflow++/lacp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader (if needed directly, though LACPDU is main focus)
#include "netflow++/buffer_pool.hpp" // For BufferPool (if generate_lacpdus is also moved here later)
#include "netflow++/logger.hpp"      // For SwitchLogger (if logging is added)
#include <iostream> // For temporary logging during development
#include <cstring>  // For memcpy
#include <algorithm> // For std::sort, std::remove, std::unique for LagConfig member_ports
#include <functional> // For std::function in configure_lag_setting

// Assuming arpa/inet.h for htons/ntohs is included via packet.hpp or lacp_manager.hpp indirectly
// If not, it might be needed here or in lacp_manager.hpp for Lacpdu struct methods.

namespace netflow {

// Default constructor for Lacpdu (if not inline in header)
Lacpdu::Lacpdu() {
    std::memset(this, 0, sizeof(Lacpdu));
    subtype = LacpDefaults::LACP_SUBTYPE;
    version_number = LacpDefaults::LACP_VERSION;
    tlv_type_actor = 0x01; actor_info_length = 0x14; // 20 bytes
    tlv_type_partner = 0x02; partner_info_length = 0x14; // 20 bytes
    tlv_type_collector = 0x03; collector_info_length = 0x10; // 16 bytes
    tlv_type_terminator = 0x00; terminator_length = 0x00;
}

// get_actor_system_id for Lacpdu (if not inline)
uint64_t Lacpdu::get_actor_system_id() const {
    uint64_t mac_part = 0;
    for(int i=0; i<6; ++i) mac_part = (mac_part << 8) | actor_system_mac[i];
    // Priority is the high part of System ID
    return (static_cast<uint64_t>(ntohs(actor_system_priority)) << 48) | mac_part;
}

// set_actor_system_id for Lacpdu (if not inline)
void Lacpdu::set_actor_system_id(uint64_t system_id) {
    actor_system_priority = htons(static_cast<uint16_t>((system_id >> 48) & 0xFFFF));
    for(int i=0; i<6; ++i) actor_system_mac[5-i] = (system_id >> (i*8)) & 0xFF;
}


// Constructor for LacpPortInfo (if not inline)
LacpPortInfo::LacpPortInfo(uint32_t phys_id)
    : port_id_physical(phys_id),
      actor_system_id_val(0), actor_port_id_val(0), actor_key_val(0), actor_state_val(0),
      partner_system_id_val(0), partner_port_id_val(0), partner_key_val(0), partner_state_val(0),
      is_active_member_of_lag(false), current_aggregator_id(0),
      current_while_timer_ticks(0), short_timeout_timer_ticks(0), long_timeout_timer_ticks(0),
      mux_state(MuxMachineState::DETACHED),
      rx_state(RxMachineState::INITIALIZE),
      periodic_tx_state(PeriodicTxState::NO_PERIODIC),
      port_priority_val(128) // Default LACP port priority
{
    actor_state_val = LacpStateFlag::AGGREGATION | LacpStateFlag::DEFAULTED;
    partner_state_val = LacpStateFlag::DEFAULTED | LacpStateFlag::EXPIRED;
}

void LacpPortInfo::set_actor_state_flag(LacpStateFlag flag, bool set) {
    if (set) actor_state_val |= static_cast<uint8_t>(flag);
    else actor_state_val &= ~static_cast<uint8_t>(flag);
}

bool LacpPortInfo::get_actor_state_flag(LacpStateFlag flag) const {
    return (actor_state_val & static_cast<uint8_t>(flag)) != 0;
}

void LacpPortInfo::set_partner_state_flag(LacpStateFlag flag, bool set) {
    if (set) partner_state_val |= static_cast<uint8_t>(flag);
    else partner_state_val &= ~static_cast<uint8_t>(flag);
}

bool LacpPortInfo::get_partner_state_flag(LacpStateFlag flag) const {
    return (partner_state_val & static_cast<uint8_t>(flag)) != 0;
}


// --- LacpManager Constructor Definition ---
LacpManager::LacpManager(uint64_t switch_base_mac, uint16_t system_priority)
    : switch_mac_address_(switch_base_mac),
      lacp_system_priority_(system_priority) {
    actor_system_id_ = (static_cast<uint64_t>(lacp_system_priority_) << 48) |
                       (switch_mac_address_ & 0x0000FFFFFFFFFFFFULL);
}

void LacpManager::set_logger(SwitchLogger* logger) {
    logger_ = logger;
}

bool LacpManager::create_lag(LagConfig& config) {
    // ... (Implementation as before) ...
    if (lags_.count(config.lag_id)) return false;
    lags_[config.lag_id] = config;
    // ... rest of the logic ...
    return true;
}

bool LacpManager::add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
    // 1. Check if the LAG ID exists
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->warning("LACP", "Attempt to add port " + std::to_string(port_id) + " to non-existent LAG ID " + std::to_string(lag_id));
        return false;
    }

    // 2. Check if the port_id is already in port_to_lag_map_
    if (port_to_lag_map_.count(port_id)) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_id) + " already belongs to LAG " + std::to_string(port_to_lag_map_[port_id]));
        return false;
    }

    // 3. Retrieve the LagConfig
    LagConfig& lag_config = lag_it->second;

    // 4. Add the port_id to the member_ports vector
    lag_config.member_ports.push_back(port_id);

    // Ensure member_ports list remains sorted and unique (good practice)
    std::sort(lag_config.member_ports.begin(), lag_config.member_ports.end());
    lag_config.member_ports.erase(std::unique(lag_config.member_ports.begin(), lag_config.member_ports.end()), lag_config.member_ports.end());

    // 5. Update the lags_ map (already done by reference with lag_config)

    // 6. Add an entry to port_to_lag_map_
    port_to_lag_map_[port_id] = lag_id;

    // 7. Call initialize_lacp_port_info to set up LACP-specific data for the port.
    // This also creates an entry in port_lacp_info_ if one doesn't exist.
    initialize_lacp_port_info(port_id, lag_config);

    // Additionally, ensure the port's LACP enabled status is consistent with the LAG's nature.
    // For now, assume LACP is enabled by default when a port is added to a LAG.
    // InterfaceManager might handle the port_enabled physical status.
    auto port_info_it = port_lacp_info_.find(port_id);
    if (port_info_it != port_lacp_info_.end()) {
        port_info_it->second.lacp_enabled = true; // Enable LACP on this port as it's now part of a LAG
        // port_info_it->second.port_enabled = true; // This should be managed by InterfaceManager
                                                 // or set explicitly based on physical port status.
                                                 // For now, assume it's operationally up for LACP.
        if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " LACP explicitly enabled due to LAG addition.");
    }


    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " added to LAG " + std::to_string(lag_id));
    return true;
}

bool LacpManager::remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
    // 1. Check if the LAG ID exists
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->warning("LACP", "Attempt to remove port " + std::to_string(port_id) + " from non-existent LAG ID " + std::to_string(lag_id));
        return false;
    }

    // 2. Retrieve the LagConfig
    LagConfig& lag_config = lag_it->second;

    // 3. Check if the port_id is actually a member of this LAG
    auto& members = lag_config.member_ports;
    auto port_member_it = std::find(members.begin(), members.end(), port_id);
    if (port_member_it == members.end()) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_id) + " is not a member of LAG " + std::to_string(lag_id));
        return false;
    }

    // 4. Remove the port_id from the member_ports vector
    members.erase(port_member_it);

    // 5. Update the lags_ map (already done by reference with lag_config)
    // If the LAG becomes empty, the LAG itself is not deleted here. delete_lag is separate.

    // 6. Remove the port_id from the port_to_lag_map_
    auto port_map_it = port_to_lag_map_.find(port_id);
    if (port_map_it != port_to_lag_map_.end() && port_map_it->second == lag_id) {
        port_to_lag_map_.erase(port_map_it);
    } else {
        // This case should ideally not happen if data is consistent
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_id) + " was not found in port_to_lag_map_ or mapped to a different LAG.");
        // Continue with removal from LAG members and LACP info as a cleanup measure.
    }

    // 7. Remove the port_id entry from the port_lacp_info_ map
    auto port_info_it = port_lacp_info_.find(port_id);
    if (port_info_it != port_lacp_info_.end()) {
        // Before removing, we might want to ensure LACP state machines are properly transitioned or reset.
        // For example, detach MUX, set port to LACP_DISABLED, etc.
        // For now, directly removing as per requirement.
        // Consider adding:
        // port_info_it->second.lacp_enabled = false;
        // port_info_it->second.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
        // run_lacp_mux_machine(port_id); // To process detachment
        // run_lacp_rx_machine(port_id); // To process LACP disabled state
        port_lacp_info_.erase(port_info_it);
    } else {
        if (logger_) logger_->warning("LACP", "No LACP info found for port " + std::to_string(port_id) + " during removal from LAG " + std::to_string(lag_id));
    }

    // Also remove from active_distributing_members if present
    auto& active_members = lag_config.active_distributing_members;
    active_members.erase(std::remove(active_members.begin(), active_members.end(), port_id), active_members.end());


    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " removed from LAG " + std::to_string(lag_id));
    return true;
}

void LacpManager::delete_lag(uint32_t lag_id) {
    // ... (Implementation as before) ...
}

// Helper function for hashing MAC address
uint32_t hash_mac(uint64_t mac) {
    // Simple XOR hash for MAC address
    uint32_t hash = 0;
    hash ^= (mac >> 32) & 0xFFFFFFFF;
    hash ^= mac & 0xFFFFFFFF;
    return hash;
}

// Helper function for hashing IP address (assuming IPv4 for now)
uint32_t hash_ip(uint32_t ip) {
    return ip; // IP addresses are already good hash values
}

// Helper function for hashing L4 port
uint32_t hash_l4_port(uint16_t port) {
    return static_cast<uint32_t>(port);
}


uint32_t LacpManager::select_egress_port(uint32_t lag_id, const Packet& pkt) const {
    // 1. Check if the lag_id exists
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->error("LACP", "select_egress_port: LAG ID " + std::to_string(lag_id) + " does not exist.");
        return 0; // Or some defined INVALID_PORT_ID
    }

    // 2. Retrieve the LagConfig
    const LagConfig& lag_config = lag_it->second;

    // 3. Check if active_distributing_members is empty
    if (lag_config.active_distributing_members.empty()) {
        if (logger_) logger_->warning("LACP", "select_egress_port: LAG ID " + std::to_string(lag_id) + " has no active distributing members.");
        return 0; // Or some defined INVALID_PORT_ID
    }

    // 4. Implement hashing logic
    uint32_t hash_value = 0;
    const EthernetHeader& eth_header = pkt.get_ethernet_header();

    // Check if packet is IP or ARP to access network/transport headers safely
    bool is_ip = eth_header.ethertype == ETHERTYPE_IP;
    // bool is_ipv6 = eth_header.ethertype == ETHERTYPE_IPV6; // Future
    // bool is_arp = eth_header.ethertype == ETHERTYPE_ARP; // Future, if ARP fields are needed for hashing

    const IpHeader* ip_header = nullptr;
    if (is_ip && pkt.get_payload().size() >= sizeof(IpHeader)) { // Ensure there's enough data for IP header
        ip_header = reinterpret_cast<const IpHeader*>(pkt.get_payload().data());
    }

    const TcpHeader* tcp_header = nullptr;
    const UdpHeader* udp_header = nullptr;
    if (ip_header) { // Only try to get L4 headers if IP header is present
        if (ip_header->protocol == IP_PROTOCOL_TCP && (pkt.get_payload().size() >= (ip_header->ihl * 4) + sizeof(TcpHeader))) {
            tcp_header = reinterpret_cast<const TcpHeader*>(pkt.get_payload().data() + (ip_header->ihl * 4));
        } else if (ip_header->protocol == IP_PROTOCOL_UDP && (pkt.get_payload().size() >= (ip_header->ihl * 4) + sizeof(UdpHeader))) {
            udp_header = reinterpret_cast<const UdpHeader*>(pkt.get_payload().data() + (ip_header->ihl * 4));
        }
    }


    switch (lag_config.hash_mode) {
        case LacpHashMode::SRC_MAC:
            hash_value = hash_mac(eth_header.src_mac);
            break;
        case LacpHashMode::DST_MAC:
            hash_value = hash_mac(eth_header.dst_mac);
            break;
        case LacpHashMode::SRC_DST_MAC:
            hash_value = hash_mac(eth_header.src_mac) ^ hash_mac(eth_header.dst_mac);
            break;
        case LacpHashMode::SRC_IP:
            if (ip_header) hash_value = hash_ip(ntohl(ip_header->src_ip));
            else hash_value = hash_mac(eth_header.src_mac); // Fallback for non-IP
            break;
        case LacpHashMode::DST_IP:
            if (ip_header) hash_value = hash_ip(ntohl(ip_header->dst_ip));
            else hash_value = hash_mac(eth_header.dst_mac); // Fallback for non-IP
            break;
        case LacpHashMode::SRC_DST_IP:
            if (ip_header) hash_value = hash_ip(ntohl(ip_header->src_ip)) ^ hash_ip(ntohl(ip_header->dst_ip));
            else hash_value = hash_mac(eth_header.src_mac) ^ hash_mac(eth_header.dst_mac); // Fallback
            break;
        case LacpHashMode::SRC_PORT:
            if (tcp_header) hash_value = hash_l4_port(ntohs(tcp_header->src_port));
            else if (udp_header) hash_value = hash_l4_port(ntohs(udp_header->src_port));
            else if (ip_header) hash_value = hash_ip(ntohl(ip_header->src_ip)); // Fallback to IP
            else hash_value = hash_mac(eth_header.src_mac); // Fallback to MAC
            break;
        case LacpHashMode::DST_PORT:
            if (tcp_header) hash_value = hash_l4_port(ntohs(tcp_header->dst_port));
            else if (udp_header) hash_value = hash_l4_port(ntohs(udp_header->dst_port));
            else if (ip_header) hash_value = hash_ip(ntohl(ip_header->dst_ip)); // Fallback to IP
            else hash_value = hash_mac(eth_header.dst_mac); // Fallback to MAC
            break;
        case LacpHashMode::SRC_DST_PORT:
            if (tcp_header) hash_value = hash_l4_port(ntohs(tcp_header->src_port)) ^ hash_l4_port(ntohs(tcp_header->dst_port));
            else if (udp_header) hash_value = hash_l4_port(ntohs(udp_header->src_port)) ^ hash_l4_port(ntohs(udp_header->dst_port));
            else if (ip_header) hash_value = hash_ip(ntohl(ip_header->src_ip)) ^ hash_ip(ntohl(ip_header->dst_ip)); // Fallback
            else hash_value = hash_mac(eth_header.src_mac) ^ hash_mac(eth_header.dst_mac); // Fallback
            break;
        case LacpHashMode::SRC_DST_IP_L4_PORT: // 5-tuple
            if (ip_header) {
                hash_value = hash_ip(ntohl(ip_header->src_ip)) ^ hash_ip(ntohl(ip_header->dst_ip)) ^ static_cast<uint32_t>(ip_header->protocol);
                if (tcp_header) {
                    hash_value ^= hash_l4_port(ntohs(tcp_header->src_port)) ^ hash_l4_port(ntohs(tcp_header->dst_port));
                } else if (udp_header) {
                    hash_value ^= hash_l4_port(ntohs(udp_header->src_port)) ^ hash_l4_port(ntohs(udp_header->dst_port));
                }
            } else { // Fallback for non-IP
                 hash_value = hash_mac(eth_header.src_mac) ^ hash_mac(eth_header.dst_mac);
            }
            break;
        default:
            // Default to L2 hash if mode is unknown or not implemented
            hash_value = hash_mac(eth_header.src_mac) ^ hash_mac(eth_header.dst_mac);
            if (logger_) logger_->warning("LACP", "select_egress_port: Unknown hash mode " + std::to_string(static_cast<int>(lag_config.hash_mode)) + ", defaulting to SRC_DST_MAC.");
            break;
    }

    // 5. Select a port
    const auto& active_members = lag_config.active_distributing_members;
    uint32_t selected_port_index = hash_value % active_members.size();
    uint32_t selected_port_id = active_members[selected_port_index];

    // 6. Log the selected port (optional)
    if (logger_ && logger_->get_level() <= LogLevel::DEBUG) { // Only log if debug level or lower
        logger_->debug("LACP", "select_egress_port: LAG ID " + std::to_string(lag_id) +
                                ", Hash Mode: " + std::to_string(static_cast<int>(lag_config.hash_mode)) +
                                ", Hash Value: " + std::to_string(hash_value) +
                                ", Selected Port Index: " + std::to_string(selected_port_index) +
                                ", Selected Port ID: " + std::to_string(selected_port_id) +
                                " from " + std::to_string(active_members.size()) + " active members.");
    }

    // 7. Return the selected port_id
    return selected_port_id;
}

void LacpManager::process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
    // ... (Implementation as before) ...
}

std::vector<Packet> LacpManager::generate_lacpdus(BufferPool& buffer_pool) {
    // ... (Implementation as before) ...
    return {}; // Placeholder
}

void LacpManager::run_lacp_timers_and_statemachines() {
    // ... (Implementation as before) ...
}

void LacpManager::initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config) {
    // ... (Implementation as before) ...
}

void LacpManager::run_lacp_rx_machine(uint32_t port_id) {
    // ... (Implementation as before) ...
}

void LacpManager::record_defaulted_partner(LacpPortInfo& port_info) { /* ... */ }
void LacpManager::record_pdu_partner_info(LacpPortInfo& port_info) { /* ... */ }
void LacpManager::update_default_selected_partner_info(LacpPortInfo& port_info, const LagConfig& lag_config) { /* ... */ }
bool LacpManager::compare_pdu_with_partner_info(const LacpPortInfo::PduActorInfo& pdu_actor_info, const LacpPortInfo& port_info) { return false; }
void LacpManager::set_current_while_timer(LacpPortInfo& port_info, bool is_short_timeout) { /* ... */ }
void LacpManager::update_ntt(LacpPortInfo& port_info) { /* ... */ }
bool LacpManager::partner_is_short_timeout(const LacpPortInfo& port_info) { return false; }

void LacpManager::run_lacp_periodic_tx_machine(uint32_t port_id) { /* ... */ }
void LacpManager::run_lacp_mux_machine(uint32_t port_id) { /* ... */ }
void LacpManager::detach_mux_from_aggregator(uint32_t port_id, LacpPortInfo& port_info) { /* ... */ }
void LacpManager::attach_mux_to_aggregator(uint32_t port_id, LacpPortInfo& port_info) { /* ... */ }
void LacpManager::disable_collecting_distributing(LacpPortInfo& port_info) { /* ... */ }
void LacpManager::enable_collecting_distributing(LacpPortInfo& port_info) { /* ... */ }
bool LacpManager::check_port_ready(const LacpPortInfo& port_info) { return false; }
void LacpManager::update_port_selection_status(uint32_t port_id, LacpPortInfo& port_info) { /* ... */ }
bool LacpManager::check_aggregator_ready_for_port(const LacpPortInfo& port_info) { return false; }
bool LacpManager::check_partner_in_sync(const LacpPortInfo& port_info) { return false; }
bool LacpManager::check_partner_in_sync_and_collecting(const LacpPortInfo& port_info) { return false; }
void LacpManager::stop_wait_while_timer(LacpPortInfo& port_info){ /* ... */ }
void LacpManager::update_port_selection_logic(uint32_t port_id_changed) { /* ... */ }


// --- New Method Implementations ---

void LacpManager::set_actor_system_priority(uint16_t priority) {
    lacp_system_priority_ = priority;
    // Recalculate Actor System ID
    actor_system_id_ = (static_cast<uint64_t>(lacp_system_priority_) << 48) |
                       (switch_mac_address_ & 0x0000FFFFFFFFFFFFULL);

    if (logger_) logger_->info("LACP", "Actor System Priority set to " + std::to_string(priority) +
                                     ". New System ID: 0x" + std::to_string(actor_system_id_)); // TODO: Hex format for ID

    // This change affects all ports' Actor System ID.
    // Update actor_system_id_val in all LacpPortInfo instances.
    // And potentially trigger NTT (Need To Transmit) for all LACP-enabled ports.
    for (auto& pair : port_lacp_info_) {
        pair.second.actor_system_id_val = actor_system_id_;
        // If LACP is active on this port, it needs to send an updated LACPDU.
        if (pair.second.lacp_enabled && pair.second.port_enabled) {
            update_ntt(pair.second);
        }
    }
    // Future: This might also trigger a re-evaluation of selection logic for all LAGs.
}

void LacpManager::set_port_lacp_priority(uint32_t port_id, uint16_t priority) {
    auto it = port_lacp_info_.find(port_id);
    if (it != port_lacp_info_.end()) {
        it->second.port_priority_val = priority;
        // Actor Port ID = 16-bit Port Priority + 16-bit Port Number
        // Port number is physical port_id for now.
        it->second.actor_port_id_val = (static_cast<uint32_t>(priority) << 16) | port_id;

        if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) +
                                         " LACP priority set to " + std::to_string(priority) +
                                         ". New Actor Port ID: 0x" + std::to_string(it->second.actor_port_id_val)); // TODO: Hex format

        // If LACP is active on this port, it needs to send an updated LACPDU.
        if (it->second.lacp_enabled && it->second.port_enabled) {
             update_ntt(it->second);
        }
        // Future: This change might affect selection logic for the LAG this port belongs to.
        // update_port_selection_logic(port_id); // Or by LAG ID if more appropriate
    } else {
        if (logger_) logger_->warning("LACP", "Attempt to set LACP priority for unknown port " + std::to_string(port_id));
    }
}

std::optional<LacpPortInfo> LacpManager::get_port_lacp_info(uint32_t port_id) const {
    auto it = port_lacp_info_.find(port_id);
    if (it != port_lacp_info_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool LacpManager::configure_lag_setting(uint32_t lag_id, std::function<void(LagConfig&)> modifier_fn) {
    auto it = lags_.find(lag_id);
    if (it != lags_.end()) {
        modifier_fn(it->second); // Apply the modification

        // After modifying LagConfig, we might need to update LACP info for all member ports
        // For example, if active_mode or lacp_rate changed, actor_state for member ports needs update.
        // If actor_admin_key changed, actor_key_val might need update.
        for (uint32_t port_id : it->second.member_ports) {
            auto port_info_it = port_lacp_info_.find(port_id);
            if (port_info_it != port_lacp_info_.end()) {
                LacpPortInfo& p_info = port_info_it->second;
                // Example: Update actor state based on new LagConfig active_mode and lacp_rate
                if (it->second.active_mode) p_info.set_actor_state_flag(LacpStateFlag::LACP_ACTIVITY, true);
                else p_info.set_actor_state_flag(LacpStateFlag::LACP_ACTIVITY, false);

                if (it->second.lacp_rate == 1) p_info.set_actor_state_flag(LacpStateFlag::LACP_TIMEOUT, true); // Fast
                else p_info.set_actor_state_flag(LacpStateFlag::LACP_TIMEOUT, false); // Slow

                // Update actor key from admin key if necessary
                p_info.actor_key_val = it->second.actor_admin_key;

                if (p_info.lacp_enabled && p_info.port_enabled) {
                     update_ntt(p_info); // Signal need to transmit new info
                }
            }
        }
        if (logger_) logger_->info("LACP", "LAG " + std::to_string(lag_id) + " configuration updated.");
        return true;
    }
    if (logger_) logger_->warning("LACP", "Attempt to configure non-existent LAG ID " + std::to_string(lag_id));
    return false;
}


} // namespace netflow
