#include "netflow++/interface_manager.hpp"
#include <map>          // For std::map
#include <vector>       // For std::vector
#include <functional>   // For std::function
#include <optional>     // For std::optional
#include <algorithm>    // For std::fill (though not directly used, good for context)

// string might not be directly needed from iostream or string header but often included.

namespace netflow {

InterfaceManager::InterfaceManager() {
    // Default constructor body. Can be empty if all members have initializers or default constructors.
    // The maps and vectors will be default-initialized.
}

void InterfaceManager::configure_port(uint32_t port_id, const PortConfig& config) {
    port_configs_[port_id] = config;
    // Ensure stats entry exists if configuring a port for the first time
    if (port_stats_.find(port_id) == port_stats_.end()) {
        port_stats_[port_id] = PortStats(); // Initialize with default (all zero) stats
    }
}

std::optional<InterfaceManager::PortConfig> InterfaceManager::get_port_config(uint32_t port_id) const {
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second;
    }
    return std::nullopt;
}

InterfaceManager::PortStats InterfaceManager::get_port_stats(uint32_t port_id) const {
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        return it->second;
    }
    return PortStats(); // Return default (all zero) stats
}

void InterfaceManager::clear_port_stats(uint32_t port_id) {
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        it->second = PortStats(); // Reset to default (all zero) stats
    }
}

bool InterfaceManager::is_port_admin_up(uint32_t port_id) const {
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second.admin_up;
    }
    return false; // Default to admin down if not configured
}

bool InterfaceManager::is_port_link_up(uint32_t port_id) const {
    auto it_state = simulated_link_state_.find(port_id);
    if (it_state != simulated_link_state_.end()) {
        return it_state->second;
    }
    return false;
}

void InterfaceManager::on_link_up(std::function<void(uint32_t port_id)> callback) {
    if (callback) {
        link_up_callbacks_.push_back(callback);
    }
}

void InterfaceManager::on_link_down(std::function<void(uint32_t port_id)> callback) {
    if (callback) {
        link_down_callbacks_.push_back(callback);
    }
}

void InterfaceManager::simulate_port_link_up(uint32_t port_id) {
    simulated_link_state_[port_id] = true;
    if (port_configs_.find(port_id) == port_configs_.end()) {
        // Optional: configure_port(port_id, PortConfig()); if callbacks rely on config
    }

    for (const auto& callback : link_up_callbacks_) {
        if (callback) {
            callback(port_id);
        }
    }
}

void InterfaceManager::simulate_port_link_down(uint32_t port_id) {
    simulated_link_state_[port_id] = false;

    for (const auto& callback : link_down_callbacks_) {
        if (callback) {
            callback(port_id);
        }
    }
}

void InterfaceManager::_increment_rx_stats(uint32_t port_id, uint64_t bytes, bool is_error, bool is_drop) {
    auto it = port_stats_.find(port_id);
    if (it == port_stats_.end()) {
        port_stats_[port_id] = PortStats();
        it = port_stats_.find(port_id);
    }
    it->second.rx_packets++;
    it->second.rx_bytes += bytes;
    if (is_error) it->second.rx_errors++;
    if (is_drop) it->second.rx_drops++;
}

void InterfaceManager::_increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error, bool is_drop) {
     auto it = port_stats_.find(port_id);
    if (it == port_stats_.end()) {
        port_stats_[port_id] = PortStats();
        it = port_stats_.find(port_id);
    }
    it->second.tx_packets++;
    it->second.tx_bytes += bytes;
    if (is_error) it->second.tx_errors++;
    if (is_drop) it->second.tx_drops++;
}

} // namespace netflow
