#include "netflow++/interface_manager.hpp"
#include <map>
#include <vector>
#include <functional>
#include <optional>
#include <algorithm>
#include <mutex> // Required for std::lock_guard

namespace netflow {

InterfaceManager::InterfaceManager() {
    // Default constructor
}

void InterfaceManager::configure_port(uint32_t port_id, const PortConfig& config) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    port_configs_[port_id] = config;
    if (port_stats_.find(port_id) == port_stats_.end()) {
        port_stats_[port_id] = PortStats();
    }
}

std::optional<InterfaceManager::PortConfig> InterfaceManager::get_port_config(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second;
    }
    return std::nullopt;
}

InterfaceManager::PortStats InterfaceManager::get_port_stats(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        return it->second;
    }
    return PortStats();
}

void InterfaceManager::clear_port_stats(uint32_t port_id) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        it->second = PortStats();
    }
}

bool InterfaceManager::is_port_admin_up(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second.admin_up;
    }
    return false;
}

// Methods related to simulated_link_state_ and callbacks are not locked by port_data_mutex_
// as they manage a separate state. If operations on these need to be atomic with
// port_configs_ or port_stats_ modifications, a more comprehensive locking strategy
// or separate mutexes for those would be needed.
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
    // If port_configs_ needs to be accessed here (e.g. to verify port exists before calling callbacks),
    // then locking for port_configs_ would be needed, and care for recursive locking if callbacks access it.
    // For now, keeping it simple:
    // if (port_configs_.find(port_id) == port_configs_.end()) { }
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
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it == port_stats_.end()) {
        port_stats_[port_id] = PortStats(); // Ensure entry exists
        it = port_stats_.find(port_id); // Get iterator to new entry
    }
    it->second.rx_packets++;
    it->second.rx_bytes += bytes;
    if (is_error) it->second.rx_errors++;
    if (is_drop) it->second.rx_drops++;
}

void InterfaceManager::_increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error, bool is_drop) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it == port_stats_.end()) {
        port_stats_[port_id] = PortStats(); // Ensure entry exists
        it = port_stats_.find(port_id); // Get iterator to new entry
    }
    it->second.tx_packets++;
    it->second.tx_bytes += bytes;
    if (is_error) it->second.tx_errors++;
    if (is_drop) it->second.tx_drops++;
}

void InterfaceManager::add_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        for (const auto& ip_conf : it->second.ip_configurations) {
            if (ip_conf.address == address && ip_conf.subnet_mask == subnet_mask) {
                return;
            }
        }
        it->second.ip_configurations.emplace_back(address, subnet_mask);
    }
}

void InterfaceManager::remove_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
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
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        return it->second.ip_configurations;
    }
    return {};
}

bool InterfaceManager::is_ip_local_to_interface(uint32_t interface_id, const IpAddress& ip) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        for (const auto& ip_conf : it->second.ip_configurations) {
            if (ip == ip_conf.address) {
                return true;
            }
        }
    }
    return false;
}

std::optional<MacAddress> InterfaceManager::get_interface_mac(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        return it->second.mac_address;
    }
    return std::nullopt;
}

std::optional<IpAddress> InterfaceManager::get_interface_ip(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        if (!it->second.ip_configurations.empty()) {
            return it->second.ip_configurations[0].address;
        }
    }
    return std::nullopt;
}

bool InterfaceManager::is_my_ip(const IpAddress& ip) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
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
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    for (const auto& pair : port_configs_) {
        for (const auto& ip_conf : pair.second.ip_configurations) {
            if (ip_conf.address == ip) {
                return pair.first;
            }
        }
    }
    return std::nullopt;
}

std::optional<MacAddress> InterfaceManager::get_mac_for_ip(const IpAddress& ip) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_); // Single lock for the operation
    std::optional<uint32_t> interface_id_opt;
    for (const auto& pair : port_configs_) { // Find interface_id
        for (const auto& ip_conf : pair.second.ip_configurations) {
            if (ip_conf.address == ip) {
                interface_id_opt = pair.first;
                break;
            }
        }
        if (interface_id_opt.has_value()) {
            break;
        }
    }

    if (interface_id_opt.has_value()) { // Get MAC using the found interface_id
        auto it_config = port_configs_.find(interface_id_opt.value());
        if (it_config != port_configs_.end()) {
            return it_config->second.mac_address;
        }
    }
    return std::nullopt;
}

// Implementations for methods moved from header
std::vector<uint32_t> InterfaceManager::get_all_interface_ids() const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    std::vector<uint32_t> ids;
    for(const auto& pair : port_configs_) {
        ids.push_back(pair.first);
    }
    return ids;
}

bool InterfaceManager::is_port_valid(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    return port_configs_.count(port_id) > 0;
}

std::vector<uint32_t> InterfaceManager::get_all_l3_interface_ids() const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    std::vector<uint32_t> l3_ids;
    for(const auto& pair : port_configs_) {
        if(!pair.second.ip_configurations.empty()) {
            l3_ids.push_back(pair.first);
        }
    }
    return l3_ids;
}

std::map<uint32_t, InterfaceManager::PortConfig> InterfaceManager::get_all_port_configs() const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    return port_configs_;
}

} // namespace netflow
