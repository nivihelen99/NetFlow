#include "netflow++/lacp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader (if needed directly, though LACPDU is main focus)
#include "netflow++/buffer_pool.hpp" // For BufferPool (if generate_lacpdus is also moved here later)
#include "netflow++/logger.hpp"      // For SwitchLogger (if logging is added)
#include <iostream> // For temporary logging during development
#include <cstring>  // For memcpy
#include <algorithm> // For std::sort, std::remove, std::unique for LagConfig member_ports

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
    // Default actor state: Aggregation=1, Defaulted=1. Others depend on config/runtime.
    actor_state_val = LacpStateFlag::AGGREGATION | LacpStateFlag::DEFAULTED;
    // Default partner state: Defaulted=1, Expired=1 (as we haven't heard from them)
    partner_state_val = LacpStateFlag::DEFAULTED | LacpStateFlag::EXPIRED;
}

void LacpPortInfo::set_actor_state_flag(LacpStateFlag flag, bool set) {
    if (set) actor_state_val |= static_cast<uint8_t>(flag);
    else actor_state_val &= ~static_cast<uint8_t>(flag);
}

bool LacpPortInfo::get_actor_state_flag(LacpStateFlag flag) const {
    return (actor_state_val & static_cast<uint8_t>(flag)) != 0;
}


// --- LacpManager Constructor Definition ---
LacpManager::LacpManager(uint64_t switch_base_mac, uint16_t system_priority)
    : switch_mac_address_(switch_base_mac),
      lacp_system_priority_(system_priority) {
    // Combine priority and MAC to form the Actor System ID
    // LACP System ID = 16-bit System Priority + 48-bit MAC Address
    actor_system_id_ = (static_cast<uint64_t>(lacp_system_priority_) << 48) |
                       (switch_mac_address_ & 0x0000FFFFFFFFFFFFULL);
    // std::cout << "LacpManager initialized. Actor System ID: " << std::hex << actor_system_id_ << std::dec << std::endl;
}

// Other LacpManager method definitions will go here...
// For example: create_lag, add_port_to_lag, process_lacpdu, generate_lacpdus, etc.
// These were already present in the header in a simplified form or defined in a previous .cpp file.
// For this subtask, only the constructor is strictly required to be defined here.
// The select_egress_port, process_lacpdu were defined inline in the header.
// generate_lacpdus, run_lacp_timers_and_statemachines etc. are still missing declarations in the header.
// We should ensure those definitions are also present if this file is being created fresh.
// For now, focusing on the constructor as per the subtask step.

void LacpManager::set_logger(SwitchLogger* logger) {
    logger_ = logger;
}

bool LacpManager::create_lag(LagConfig& config) {
    if (config.lag_id == 0) {
        if (logger_) logger_->warning("LACP", "Attempt to create LAG with ID 0 failed.");
        return false;
    }
    if (lags_.count(config.lag_id)) {
        if (logger_) logger_->error("LACP", "LAG ID " + std::to_string(config.lag_id) + " already exists.");
        return false;
    }

    for (uint32_t port_id : config.member_ports) {
        if (port_to_lag_map_.count(port_id)) {
            if (logger_) logger_->error("LACP", "Port " + std::to_string(port_id) + " is already part of LAG " + std::to_string(port_to_lag_map_[port_id]));
            return false;
        }
    }

    lags_[config.lag_id] = config;
    std::sort(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end());
    lags_[config.lag_id].member_ports.erase(
        std::unique(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end()),
        lags_[config.lag_id].member_ports.end()
    );

    for (uint32_t port_id : lags_[config.lag_id].member_ports) {
        port_to_lag_map_[port_id] = config.lag_id;
        // Also initialize LACP port info for this port
        initialize_lacp_port_info(port_id, lags_[config.lag_id]);
    }
    if (logger_) logger_->info("LACP", "LAG " + std::to_string(config.lag_id) + " created.");
    return true;
}

bool LacpManager::add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->error("LACP", "LAG " + std::to_string(lag_id) + " does not exist, cannot add port " + std::to_string(port_id));
        return false;
    }

    auto port_map_it = port_to_lag_map_.find(port_id);
    if (port_map_it != port_to_lag_map_.end()) {
        if (port_map_it->second == lag_id) {
            if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + " already in LAG " + std::to_string(lag_id));
            return true; // Port already in this LAG
        } else {
            if (logger_) logger_->error("LACP", "Port " + std::to_string(port_id) + " is already part of a different LAG (" + std::to_string(port_map_it->second) + ").");
            return false; // Port already in a different LAG
        }
    }

    lag_it->second.member_ports.push_back(port_id);
    std::sort(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end());
    lag_it->second.member_ports.erase(
        std::unique(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end()),
        lag_it->second.member_ports.end()
    );
    port_to_lag_map_[port_id] = lag_id;
    initialize_lacp_port_info(port_id, lag_it->second);
    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " added to LAG " + std::to_string(lag_id));
    return true;
}

bool LacpManager::remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->warning("LACP", "LAG " + std::to_string(lag_id) + " not found for port " + std::to_string(port_id) + " removal.");
        return false;
    }

    auto port_map_it = port_to_lag_map_.find(port_id);
    if (port_map_it == port_to_lag_map_.end() || port_map_it->second != lag_id) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_id) + " is not part of LAG " + std::to_string(lag_id));
        return false;
    }

    auto& members = lag_it->second.member_ports;
    members.erase(std::remove(members.begin(), members.end(), port_id), members.end());
    port_to_lag_map_.erase(port_id);
    port_lacp_info_.erase(port_id); // Remove LACP specific info for the port

    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " removed from LAG " + std::to_string(lag_id));
    if (members.empty()) {
        if (logger_) logger_->warning("LACP", "LAG " + std::to_string(lag_id) + " has no more members.");
    }
    return true;
}

void LacpManager::delete_lag(uint32_t lag_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it != lags_.end()) {
        for (uint32_t port_id : lag_it->second.member_ports) {
            port_to_lag_map_.erase(port_id);
            port_lacp_info_.erase(port_id);
        }
        lags_.erase(lag_id);
        if (logger_) logger_->info("LACP", "LAG " + std::to_string(lag_id) + " deleted.");
    } else {
        if (logger_) logger_->warning("LACP", "Attempt to delete non-existent LAG ID " + std::to_string(lag_id));
    }
}

uint32_t LacpManager::select_egress_port(uint32_t lag_id, const Packet& pkt) const {
    auto it = lags_.find(lag_id);
    if (it == lags_.end() || it->second.member_ports.empty()) {
        if (logger_) logger_->error("LACP", "Invalid LAG ID " + std::to_string(lag_id) + " or no member ports for selection.");
        return 0;
    }

    const LagConfig& lag_config = it->second;
    // Filter for active members based on LACP state (COLLECTING and DISTRIBUTING flags)
    std::vector<uint32_t> active_distributing_members;
    for (uint32_t port_id : lag_config.member_ports) {
        auto port_info_it = port_lacp_info_.find(port_id);
        if (port_info_it != port_lacp_info_.end()) {
            const LacpPortInfo& p_info = port_info_it->second;
            if (p_info.get_actor_state_flag(LacpStateFlag::COLLECTING) &&
                p_info.get_actor_state_flag(LacpStateFlag::DISTRIBUTING)) {
                active_distributing_members.push_back(port_id);
            }
        }
    }

    if (active_distributing_members.empty()) {
         if (logger_) logger_->warning("LACP", "No active distributing members in LAG " + std::to_string(lag_id) + " for packet selection.");
         // Fallback to all configured members if no one is actively distributing
         // This might not be desired, depends on strictness. For now, let's try configured members.
         if (lag_config.member_ports.empty()){
            if (logger_) logger_->error("LACP", "LAG " + std::to_string(lag_id) + " has no configured members at all.");
            return 0;
         }
         const std::vector<uint32_t>& members_to_use = lag_config.member_ports;
          uint32_t hash_val = 0;
          if(pkt.src_mac().has_value()){ // Basic L2 hash
              for(int i=0; i<6; ++i) hash_val += pkt.src_mac().value().bytes[i];
          }
          return members_to_use[hash_val % members_to_use.size()];
    }


    // TODO: Implement actual hashing based on lag_config.hash_mode and packet (pkt)
    // For now, simple L2 hash on active_distributing_members
    uint32_t hash_val = 0;
    if(pkt.src_mac().has_value()){
        for(int i=0; i<6; ++i) hash_val += pkt.src_mac().value().bytes[i];
    }
    return active_distributing_members[hash_val % active_distributing_members.size()];
}

void LacpManager::process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
    if (logger_) {
        logger_->debug("LACP", "Received LACPDU on port " + std::to_string(ingress_port_id) +
                              ". Size: " + std::to_string(lacpdu_packet.get_buffer()->get_data_length()));
    }
    // Placeholder for full LACPDU processing logic
    // 1. Decode LACPDU
    // 2. Update port_lacp_info_ for ingress_port_id
    // 3. Call run_lacp_rx_machine(ingress_port_id)
    // 4. Potentially trigger other state machines or updates.
}

// Placeholder definitions for other methods.
// These would need their full logic from the previous LACP subtask AND declarations in the header.

std::vector<Packet> LacpManager::generate_lacpdus(BufferPool& buffer_pool) {
    if (logger_) logger_->debug("LACP", "generate_lacpdus called");
    return {};
}

void LacpManager::run_lacp_timers_and_statemachines() {
    if (logger_) logger_->debug("LACP", "run_lacp_timers_and_statemachines called");
    for(auto const& [port_id, lacp_info] : port_lacp_info_){
        // run_lacp_rx_machine(port_id); // Rx machine is typically event-driven by PDU arrival or timer expiry
        // run_lacp_periodic_tx_machine(port_id);
        // run_lacp_mux_machine(port_id);
    }
}
void LacpManager::initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config) {
    // Placeholder
}
void LacpManager::run_lacp_rx_machine(uint32_t port_id) {
    // Placeholder
}
void LacpManager::run_lacp_periodic_tx_machine(uint32_t port_id) {
    // Placeholder
}
void LacpManager::run_lacp_mux_machine(uint32_t port_id) {
    // Placeholder
}
void LacpManager::update_port_selection_logic(uint32_t port_id) {
    // Placeholder
}


} // namespace netflow
