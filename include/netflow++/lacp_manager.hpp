#ifndef NETFLOW_LACP_MANAGER_HPP
#define NETFLOW_LACP_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <optional>
#include <algorithm> // For std::sort, std::unique, std::remove
#include <string>    // Potentially for names or logging
#include <iostream>  // For placeholder logging

#include "packet.hpp" // For Packet class, used in select_egress_port and process_lacpdu

// Forward declare PacketClassifier if its FlowKey might be used directly for hashing inspiration
// namespace netflow { class PacketClassifier; }

namespace netflow {

enum class LacpHashMode {
    SRC_MAC,
    DST_MAC,
    SRC_DST_MAC,        // L2 hash
    SRC_IP,
    DST_IP,
    SRC_DST_IP,         // L3 hash
    SRC_PORT,
    DST_PORT,
    SRC_DST_PORT,       // L4 hash
    SRC_DST_IP_L4_PORT  // Common 5-tuple hash
};

struct LagConfig {
    uint32_t lag_id = 0; // Unique identifier for the Link Aggregation Group
    std::vector<uint32_t> member_ports; // List of physical port IDs in this LAG
    LacpHashMode hash_mode = LacpHashMode::SRC_DST_IP_L4_PORT; // Hashing mode for load balancing
    bool active_mode = true;  // LACP mode: true for Active, false for Passive
    // Other LACP parameters could be added here:
    // uint16_t system_priority = 32768;
    // MacAddress system_id_mac; // System's base MAC for LACP
    // std::map<uint32_t, uint16_t> port_priorities; // port_id -> LACP port priority

    LagConfig() = default;
};

class LacpManager {
public:
    LacpManager() = default;

    // Creates a new Link Aggregation Group (LAG).
    // Returns true if successful, false if LAG ID already exists.
    bool create_lag(const LagConfig& config) {
        if (config.lag_id == 0) { // 0 might be an invalid/reserved LAG ID
            // std::cerr << "Error: LAG ID 0 is invalid." << std::endl;
            return false;
        }
        if (lags_.count(config.lag_id)) {
            // std::cerr << "Error: LAG ID " << config.lag_id << " already exists." << std::endl;
            return false;
        }

        // Check if any proposed member ports are already in other LAGs
        for (uint32_t port_id : config.member_ports) {
            if (port_to_lag_map_.count(port_id)) {
                // std::cerr << "Error: Port " << port_id << " is already part of LAG "
                //           << port_to_lag_map_[port_id] << "." << std::endl;
                return false; // Strict: port cannot be in multiple LAGs initially
            }
        }

        lags_[config.lag_id] = config;
        // Sort and unique member_ports in the stored config
        std::sort(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end());
        lags_[config.lag_id].member_ports.erase(
            std::unique(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end()),
            lags_[config.lag_id].member_ports.end()
        );

        for (uint32_t port_id : lags_[config.lag_id].member_ports) {
            port_to_lag_map_[port_id] = config.lag_id;
        }
        // std::cout << "LAG " << config.lag_id << " created." << std::endl;
        return true;
    }

    // Adds a physical port to an existing LAG.
    // Returns true if successful.
    bool add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            // std::cerr << "Error: LAG " << lag_id << " does not exist." << std::endl;
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it != port_to_lag_map_.end()) {
            if (port_map_it->second == lag_id) {
                return true; // Port already in this LAG
            } else {
                // std::cerr << "Error: Port " << port_id << " is already part of a different LAG ("
                //           << port_map_it->second << ")." << std::endl;
                return false; // Port already in a different LAG
            }
        }

        lag_it->second.member_ports.push_back(port_id);
        // Ensure no duplicates and maintain sorted order
        std::sort(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end());
        lag_it->second.member_ports.erase(
            std::unique(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end()),
            lag_it->second.member_ports.end()
        );
        port_to_lag_map_[port_id] = lag_id;
        // std::cout << "Port " << port_id << " added to LAG " << lag_id << "." << std::endl;
        return true;
    }

    // Removes a physical port from a LAG.
    // Returns true if successful.
    bool remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            // std::cerr << "Warning: LAG " << lag_id << " not found for port removal." << std::endl;
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it == port_to_lag_map_.end() || port_map_it->second != lag_id) {
            // std::cerr << "Warning: Port " << port_id << " is not part of LAG " << lag_id << "." << std::endl;
            return false; // Port not in this LAG
        }

        auto& members = lag_it->second.member_ports;
        members.erase(std::remove(members.begin(), members.end(), port_id), members.end());
        port_to_lag_map_.erase(port_id);

        // std::cout << "Port " << port_id << " removed from LAG " << lag_id << "." << std::endl;
        if (members.empty()) {
            // Optionally remove LAG if no members left, or leave it configured but inactive.
            // For now, let's leave it, user can explicitly delete_lag.
            // std::cout << "Warning: LAG " << lag_id << " has no more members." << std::endl;
        }
        return true;
    }

    // Deletes an entire LAG.
    void delete_lag(uint32_t lag_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it != lags_.end()) {
            for (uint32_t port_id : lag_it->second.member_ports) {
                port_to_lag_map_.erase(port_id);
            }
            lags_.erase(lag_id);
            // std::cout << "LAG " << lag_id << " deleted." << std::endl;
        }
    }

    // Placeholder: Selects an egress port from a LAG based on packet hash.
    // Actual hashing and selection is more complex and depends on active/selected members.
    // Returns a physical port_id.
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt) const {
        auto it = lags_.find(lag_id);
        if (it == lags_.end() || it->second.member_ports.empty()) {
            // std::cerr << "Error: Invalid LAG ID " << lag_id << " or no member ports for selection." << std::endl;
            return 0; // 0 could signify an invalid port or "drop". Needs clear definition.
                      // Or throw an exception for critical error.
        }

        const LagConfig& lag_config = it->second;
        const std::vector<uint32_t>& members = lag_config.member_ports;

        // TODO: Implement actual hashing based on lag_config.hash_mode and packet (pkt)
        // For now, simple round-robin or first port.
        // Example using a very simple hash of some packet fields:
        // PacketClassifier::FlowKey flow_key = some_classifier_instance.extract_flow_key(pkt);
        // uint32_t hash = some_classifier_instance.hash_flow(flow_key);
        // uint32_t member_index = hash % members.size();
        // return members[member_index];

        // Using a mutable index for simple round-robin (if LacpManager is not const for this method)
        // Or, if it must be const, then hash is better.
        // For this placeholder with const method:
        if (!members.empty()) {
             // Simplistic: hash source MAC to choose port (very basic)
            uint32_t hash_val = 0;
            if(pkt.src_mac().has_value()){
                for(int i=0; i<6; ++i) hash_val += pkt.src_mac().value().bytes[i];
            }
            return members[hash_val % members.size()];
        }

        return members[0]; // Fallback to first available port if all else fails
    }

    // Placeholder: Actual LACPDU processing is complex (state machines, timers, etc.)
    void process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
        // 1. Decode LACPDU from lacpdu_packet.
        // 2. Check if ingress_port_id is part of a LAG configured for LACP (active or passive).
        // 3. Update actor/partner information for the port based on received LACPDU.
        // 4. Run LACP state machines (Receive, Mux, Periodic, Churn Detection etc.).
        //    This involves:
        //    - Actor state updates (e.g., LACP_Activity, LACP_Timeout, Aggregation, Sync, Collecting, Distributing).
        //    - Partner state updates.
        //    - Port selection logic to determine which ports can be aggregated based on compatible actor/partner info.
        //    - Attaching/detaching ports from the aggregator.
        // std::cout << "Placeholder: Received LACPDU on port " << ingress_port_id
        //           << ". (Size: " << lacpdu_packet.get_buffer()->size << ")" << std::endl;
    }

    // Checks if a physical port is part of any LAG.
    bool is_port_in_lag(uint32_t port_id) const {
        return port_to_lag_map_.count(port_id);
    }

    // Gets the LAG ID for a given physical port, if it's part of one.
    std::optional<uint32_t> get_lag_for_port(uint32_t port_id) const {
        auto it = port_to_lag_map_.find(port_id);
        if (it != port_to_lag_map_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves the configuration for a specific LAG.
    std::optional<LagConfig> get_lag_config(uint32_t lag_id) const {
        auto it = lags_.find(lag_id);
        if (it != lags_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves all configured LAGs
    const std::map<uint32_t, LagConfig>& get_all_lags() const {
        return lags_;
    }

private:
    std::map<uint32_t, LagConfig> lags_; // lag_id -> LagConfig
    std::map<uint32_t, uint32_t> port_to_lag_map_; // physical_port_id -> lag_id

    // For a more robust round-robin in select_egress_port (if it were non-const):
    // mutable std::map<uint32_t, size_t> current_selection_index_;
};

} // namespace netflow

#endif // NETFLOW_LACP_MANAGER_HPP
