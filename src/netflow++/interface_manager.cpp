#include "netflow++/interface_manager.hpp"
#include "netflow++/logger.hpp" // Ensure logger is included
#include "netflow++/acl_manager.hpp" // Ensure AclManager is included
#include <map>
#include <vector>
#include <functional>
#include <optional>
#include <algorithm>
#include <mutex>

namespace netflow {

InterfaceManager::InterfaceManager(SwitchLogger& logger, AclManager& acl_mgr /*, Switch* sw_ptr */)
    : logger_(logger), acl_manager_(acl_mgr) /*, switch_ptr_(sw_ptr) */ {
    logger_.log(LogLevel::DEBUG, "InterfaceManager", "InterfaceManager initialized.");
}

void InterfaceManager::configure_port(uint32_t port_id, const PortConfig& config) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    port_configs_[port_id] = config;
    if (port_stats_.find(port_id) == port_stats_.end()) {
        port_stats_[port_id] = PortStats();
    }
    logger_.log(LogLevel::INFO, "InterfaceManager", "Port " + std::to_string(port_id) + " configured.");
}

std::optional<InterfaceManager::PortConfig> InterfaceManager::get_port_config(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second;
    }
    logger_.log(LogLevel::DEBUG, "InterfaceManager", "Port config not found for port " + std::to_string(port_id));
    return std::nullopt;
}

InterfaceManager::PortStats InterfaceManager::get_port_stats(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        return it->second;
    }
    logger_.log(LogLevel::DEBUG, "InterfaceManager", "Port stats not found for port " + std::to_string(port_id) + ", returning empty stats.");
    return PortStats();
}

void InterfaceManager::clear_port_stats(uint32_t port_id) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_stats_.find(port_id);
    if (it != port_stats_.end()) {
        it->second = PortStats();
        logger_.log(LogLevel::INFO, "InterfaceManager", "Cleared stats for port " + std::to_string(port_id));
    } else {
        logger_.log(LogLevel::WARNING, "InterfaceManager", "Attempted to clear stats for non-existent port " + std::to_string(port_id));
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

bool InterfaceManager::is_port_link_up(uint32_t port_id) const {
    // No lock needed for simulated_link_state_ if it's managed separately or atomicity is not critical with config changes.
    // However, if port_id validity check against port_configs_ is desired, locking would be needed.
    // For now, assume simulated_link_state_ can be checked directly.
    auto it_state = simulated_link_state_.find(port_id);
    if (it_state != simulated_link_state_.end()) {
        return it_state->second;
    }
    return false; // Default to link down if no simulation state for port
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
    if (!is_port_valid(port_id)) { // Check validity using the method that locks
        logger_.log(LogLevel::WARNING, "InterfaceManager", "Cannot simulate link up for non-existent port " + std::to_string(port_id));
        return;
    }
    simulated_link_state_[port_id] = true;
    logger_.log(LogLevel::INFO, "InterfaceManager", "Port " + std::to_string(port_id) + " link simulated UP.");
    for (const auto& callback : link_up_callbacks_) {
        if (callback) {
            callback(port_id);
        }
    }
}

void InterfaceManager::simulate_port_link_down(uint32_t port_id) {
     if (!is_port_valid(port_id)) {
        logger_.log(LogLevel::WARNING, "InterfaceManager", "Cannot simulate link down for non-existent port " + std::to_string(port_id));
        return;
    }
    simulated_link_state_[port_id] = false;
    logger_.log(LogLevel::INFO, "InterfaceManager", "Port " + std::to_string(port_id) + " link simulated DOWN.");
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
        port_stats_[port_id] = PortStats();
        it = port_stats_.find(port_id);
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
        port_stats_[port_id] = PortStats();
        it = port_stats_.find(port_id);
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
            if (ip_conf.address == address) { // Simplified check: only one IP of same value, regardless of mask
                logger_.log(LogLevel::WARNING, "InterfaceManager", "IP address " + logger_.ip_to_string(address) + " already exists on interface " + std::to_string(interface_id));
                return;
            }
        }
        it->second.ip_configurations.emplace_back(address, subnet_mask);
        logger_.log(LogLevel::INFO, "InterfaceManager", "Added IP " + logger_.ip_to_string(address) + "/" + logger_.ip_to_string(subnet_mask) + " to interface " + std::to_string(interface_id));
    } else {
        logger_.log(LogLevel::ERROR, "InterfaceManager", "Cannot add IP to non-existent interface " + std::to_string(interface_id));
    }
}

void InterfaceManager::remove_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        auto& ip_configs = it->second.ip_configurations;
        auto original_size = ip_configs.size();
        ip_configs.erase(
            std::remove_if(ip_configs.begin(), ip_configs.end(),
                           [&](const InterfaceIpConfig& ipc) {
                               return ipc.address == address && ipc.subnet_mask == subnet_mask;
                           }),
            ip_configs.end());
        if (ip_configs.size() < original_size) {
            logger_.log(LogLevel::INFO, "InterfaceManager", "Removed IP " + logger_.ip_to_string(address) + "/" + logger_.ip_to_string(subnet_mask) + " from interface " + std::to_string(interface_id));
        }
    } else {
        logger_.log(LogLevel::ERROR, "InterfaceManager", "Cannot remove IP from non-existent interface " + std::to_string(interface_id));
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
    // ... (implementation unchanged)
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
    // ... (implementation unchanged)
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(interface_id);
    if (it != port_configs_.end()) {
        return it->second.mac_address;
    }
    return std::nullopt;
}
std::optional<IpAddress> InterfaceManager::get_interface_ip(uint32_t interface_id) const {
    // ... (implementation unchanged)
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
    // ... (implementation unchanged)
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
    // ... (implementation unchanged)
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
    // ... (implementation unchanged)
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    std::optional<uint32_t> interface_id_opt;
    for (const auto& pair : port_configs_) {
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
    if (interface_id_opt.has_value()) {
        auto it_config = port_configs_.find(interface_id_opt.value());
        if (it_config != port_configs_.end()) {
            return it_config->second.mac_address;
        }
    }
    return std::nullopt;
}
std::vector<uint32_t> InterfaceManager::get_all_interface_ids() const {
    // ... (implementation unchanged)
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    std::vector<uint32_t> ids;
    for(const auto& pair : port_configs_) {
        ids.push_back(pair.first);
    }
    return ids;
}
bool InterfaceManager::is_port_valid(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    // A port is valid if it has a configuration entry.
    // Or, if num_ports_ was a member, check against that.
    // For now, based on config existence.
    return port_configs_.count(port_id) > 0;
}
std::vector<uint32_t> InterfaceManager::get_all_l3_interface_ids() const {
    // ... (implementation unchanged)
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

// --- New ACL related method implementations ---
bool InterfaceManager::apply_acl_to_interface(uint32_t port_id, const std::string& acl_name, AclDirection direction) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it == port_configs_.end()) {
        logger_.log(LogLevel::ERROR, "InterfaceManager", "Port " + std::to_string(port_id) + " not found for applying ACL.");
        return false;
    }

    // Verify ACL name exists in AclManager
    // This requires AclManager to have a method like acl_exists() or get_acl_names()
    // For now, assume AclManager::get_all_rules(acl_name) would return empty if ACL doesn't exist,
    // or rely on ManagementService to validate ACL name before calling this.
    // A better approach: acl_manager_.acl_exists(acl_name)
    bool acl_exists = false;
    auto acl_names = acl_manager_.get_acl_names();
    if (std::find(acl_names.begin(), acl_names.end(), acl_name) != acl_names.end()) {
        acl_exists = true;
    }

    if (!acl_exists && !acl_name.empty()) { // Allow clearing by applying an empty name if that's the convention
        logger_.log(LogLevel::ERROR, "InterfaceManager", "ACL '" + acl_name + "' not found in AclManager. Cannot apply to port " + std::to_string(port_id));
        return false;
    }

    std::string dir_str = (direction == AclDirection::INGRESS) ? "ingress" : "egress";
    if (direction == AclDirection::INGRESS) {
        it->second.ingress_acl_name = acl_name.empty() ? std::nullopt : std::optional<std::string>(acl_name);
    } else { // EGRESS
        it->second.egress_acl_name = acl_name.empty() ? std::nullopt : std::optional<std::string>(acl_name);
    }
    logger_.log(LogLevel::INFO, "InterfaceManager", "Applied ACL '" + acl_name + "' to port " + std::to_string(port_id) + " for " + dir_str + " direction.");
    return true;
}

bool InterfaceManager::remove_acl_from_interface(uint32_t port_id, AclDirection direction) {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it == port_configs_.end()) {
        logger_.log(LogLevel::ERROR, "InterfaceManager", "Port " + std::to_string(port_id) + " not found for removing ACL.");
        return false;
    }

    std::string dir_str = (direction == AclDirection::INGRESS) ? "ingress" : "egress";
    std::optional<std::string> removed_acl_name;

    if (direction == AclDirection::INGRESS) {
        removed_acl_name = it->second.ingress_acl_name;
        it->second.ingress_acl_name = std::nullopt;
    } else { // EGRESS
        removed_acl_name = it->second.egress_acl_name;
        it->second.egress_acl_name = std::nullopt;
    }
    if(removed_acl_name.has_value() && !removed_acl_name.value().empty()){
        logger_.log(LogLevel::INFO, "InterfaceManager", "Removed ACL '" + removed_acl_name.value() + "' from port " + std::to_string(port_id) + " for " + dir_str + " direction.");
    } else {
        logger_.log(LogLevel::INFO, "InterfaceManager", "No ACL was applied on port " + std::to_string(port_id) + " for " + dir_str + " direction. No action taken.");
    }
    return true;
}

std::optional<std::string> InterfaceManager::get_applied_acl_name(uint32_t port_id, AclDirection direction) const {
    std::lock_guard<std::mutex> lock(port_data_mutex_);
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        if (direction == AclDirection::INGRESS) {
            return it->second.ingress_acl_name;
        } else { // EGRESS
            return it->second.egress_acl_name;
        }
    }
    logger_.log(LogLevel::DEBUG, "InterfaceManager", "Port " + std::to_string(port_id) + " not found for getting applied ACL name.");
    return std::nullopt;
}


} // namespace netflow
