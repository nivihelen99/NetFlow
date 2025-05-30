#include "netflow_plus_plus/port/interface_manager.hpp"
#include <iostream> // For placeholder messages in callbacks

namespace netflow_plus_plus {
namespace port {

InterfaceManager::InterfaceManager() {
    // Initialize with some default ports perhaps, or leave empty
}

void InterfaceManager::configure_port(uint32_t port, const PortConfig& config) {
    port_configs_[port] = config;
    // Potentially trigger actions based on config change, e.g., if admin_up changed.
    // if (config.admin_up && link_up_callback_) {
    //     // This is a simplification; actual link up is a separate event.
    //     // link_up_callback_(port);
    // } else if (!config.admin_up && link_down_callback_) {
    //     // link_down_callback_(port);
    // }
}

PortConfig InterfaceManager::get_port_config(uint32_t port) const {
    auto it = port_configs_.find(port);
    if (it != port_configs_.end()) {
        return it->second;
    }
    return PortConfig{}; // Return default config if port not found
}

PortStats InterfaceManager::get_port_stats(uint32_t port) const {
    auto it = port_stats_.find(port);
    if (it != port_stats_.end()) {
        return it->second;
    }
    return PortStats{}; // Return empty/default stats if port not found
}

void InterfaceManager::clear_port_stats(uint32_t port) {
    auto it = port_stats_.find(port);
    if (it != port_stats_.end()) {
        it->second = PortStats{}; // Reset to default (all zeros)
    } else {
        // If port doesn't exist in stats map yet, create it with zeroed stats
        port_stats_[port] = PortStats{};
    }
}

bool InterfaceManager::is_port_up(uint32_t port) const {
    auto it = port_configs_.find(port);
    if (it != port_configs_.end()) {
        // In a more complex system, this would also check operational status
        return it->second.admin_up;
    }
    return false; // Port not configured, considered down
}

void InterfaceManager::set_port_admin_state(uint32_t port, bool up) {
    auto it = port_configs_.find(port);
    if (it != port_configs_.end()) {
        bool old_state = it->second.admin_up;
        it->second.admin_up = up;
        // if (old_state != up) {
        //     if (up && link_up_callback_) { /* simulate_link_up(port); */ }
        //     else if (!up && link_down_callback_) { /* simulate_link_down(port); */ }
        // }
    } else {
        // Port not configured yet, create a default config and set its admin state
        PortConfig new_config;
        new_config.admin_up = up;
        port_configs_[port] = new_config;
        // if (up && link_up_callback_) { /* simulate_link_up(port); */ }
    }
}

void InterfaceManager::on_link_up(std::function<void(uint32_t)> callback) {
    link_up_callback_ = callback;
}

void InterfaceManager::on_link_down(std::function<void(uint32_t)> callback) {
    link_down_callback_ = callback;
}

void InterfaceManager::simulate_link_up(uint32_t port_id) {
    if (link_up_callback_) {
        link_up_callback_(port_id);
    } else {
        std::cout << "Link up event for port " << port_id << " (no callback registered)." << std::endl;
    }
}

void InterfaceManager::simulate_link_down(uint32_t port_id) {
     if (link_down_callback_) {
        link_down_callback_(port_id);
    } else {
        std::cout << "Link down event for port " << port_id << " (no callback registered)." << std::endl;
    }
}

} // namespace port
} // namespace netflow_plus_plus
