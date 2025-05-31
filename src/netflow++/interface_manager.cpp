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

// --- IP Configuration Method Implementations ---

void InterfaceManager::add_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask) {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        // Check if already exists
        for (const auto& ip_conf : it->second.ip_configurations) {
            if (ip_conf.address == address && ip_conf.subnet_mask == subnet_mask) {
                return; // Already exists
            }
        }
        it->second.ip_configurations.emplace_back(address, subnet_mask);
    } else {
        // Optionally create a default PortConfig if interface_id is new, or log an error
        // For now, assume port must be configured first via configure_port
    }
}

void InterfaceManager::remove_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask) {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        auto& ip_configs = it->second.ip_configurations;
        ip_configs.erase(
            std::remove_if(ip_configs.begin(), ip_configs.end(),
                           [&](const InterfaceIpConfig& ipc) {
                               return ipc.address == address && ipc.subnet_mask == subnet_mask;
                           }),
            ip_configs.end());
    }
}

std::vector<InterfaceIpConfig> InterfaceManager::get_interface_ip_configs(uint32_t interface_id) const {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        return it->second.ip_configurations;
    }
    return {}; // Return empty vector if interface not found
}

// Replaces the stub from the header
bool InterfaceManager::is_ip_local_to_interface(uint32_t interface_id, const IpAddress& ip) const {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        for (const auto& ip_conf : it->second.ip_configurations) {
            // For ARP/ICMP responding, we check if the IP is directly assigned to this interface.
            if (ip == ip_conf.address) {
                return true;
            }
            // The broader subnet check: (ip & ip_conf.subnet_mask) == (ip_conf.address & ip_conf.subnet_mask)
            // would be used for routing logic (i.e., can this interface forward to an IP on its connected subnet)
            // but not typically for checking if an IP *is* the interface's own address.
        }
    }
    return false;
}

// Replaces the stub from the header
std::optional<MacAddress> InterfaceManager::get_interface_mac(uint32_t interface_id) const {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        return it->second.mac_address; // Assumes mac_address is now part of PortConfig
    }
    return std::nullopt;
}

// Replaces the stub from the header
std::optional<IpAddress> InterfaceManager::get_interface_ip(uint32_t interface_id) const {
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        if (!it->second.ip_configurations.empty()) {
            return it->second.ip_configurations[0].address; // Return primary IP (first configured)
        }
    }
    return std::nullopt;
}

bool InterfaceManager::is_my_ip(const IpAddress& ip) const {
    for (const auto& pair : port_configs_) {
        for (const auto& ip_conf : pair.second.ip_configurations) {
            if (ip_conf.address == ip) {
                return true;
            }
        }
    }
    return false;
}

std::optional<uint32_t> InterfaceManager::find_interface_for_ip(const IpAddress& ip) const {
    for (const auto& pair : port_configs_) {
        // Using is_ip_local_to_interface to check if this IP is assigned to this interface
        if (is_ip_local_to_interface(pair.first, ip)) {
            return pair.first;
        }
    }
    return std::nullopt;
}

std::optional<MacAddress> InterfaceManager::get_mac_for_ip(const IpAddress& ip) const {
    std::optional<uint32_t> interface_id_opt = find_interface_for_ip(ip);
    if (interface_id_opt) {
        return get_interface_mac(*interface_id_opt);
    }
    return std::nullopt;
}

} // namespace netflow
