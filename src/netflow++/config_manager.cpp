#include "netflow++/config_manager.hpp"
#include "netflow++/switch.hpp" // Required for the full definition of Switch and its managers
#include "netflow++/interface_manager.hpp" // Specifically for InterfaceManager::PortConfig
// Other manager headers might be needed if apply_config handles them directly.

#include <iostream> // For std::cerr/cout placeholders
#include <charconv> // For std::from_chars

namespace netflow {

// Definition of apply_config moved here
void ConfigManager::apply_config(const ConfigurationData& config_data_to_apply, netflow::Switch& target_switch) {
    if (logger_) logger_->info("ConfigApply", "Starting to apply configuration.");

    for (const auto& pair : config_data_to_apply) {
        const std::string& path = pair.first;
        const ConfigValue& value = pair.second;
        if (logger_) logger_->debug("ConfigApply", "Processing: " + path);

        std::string component, id_str, param;
        size_t pos1 = path.find('.');
        size_t pos2 = (pos1 == std::string::npos) ? std::string::npos : path.find('.', pos1 + 1);

        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            component = path.substr(0, pos1);
            id_str = path.substr(pos1 + 1, pos2 - (pos1 + 1));
            param = path.substr(pos2 + 1);
        } else {
            if (path == "global.hostname") {
                if (auto* str_val = std::get_if<std::string>(&value)) {
                    // target_switch.set_hostname(*str_val); // Switch would need this method
                    if (logger_) logger_->info("ConfigApply", "Set global.hostname to " + *str_val);
                } else {
                    if (logger_) logger_->error("ConfigApply", "Invalid type for global.hostname");
                }
            } else {
                 if (logger_) logger_->warning("ConfigApply", "Unrecognized path " + path);
            }
            continue;
        }

        if (component == "port") {
            uint32_t port_id;
            auto conv_result = std::from_chars(id_str.data(), id_str.data() + id_str.size(), port_id);
            if (conv_result.ec == std::errc() && conv_result.ptr == id_str.data() + id_str.size()) {
                InterfaceManager::PortConfig port_cfg = target_switch.interface_manager_.get_port_config(port_id).value_or(InterfaceManager::PortConfig());
                bool config_changed = false;

                if (param == "speed_mbps") {
                    if (auto* val_ptr = std::get_if<uint32_t>(&value)) { port_cfg.speed_mbps = *val_ptr; config_changed = true; }
                    else if (auto* val_ptr_int = std::get_if<int>(&value)) { port_cfg.speed_mbps = static_cast<uint32_t>(*val_ptr_int); config_changed = true; }
                    else { if (logger_) logger_->error("ConfigApply", "Invalid type for port." + id_str + ".speed_mbps"); }
                } else if (param == "admin_up") {
                    if (auto* val_ptr = std::get_if<bool>(&value)) { port_cfg.admin_up = *val_ptr; config_changed = true; }
                    else { if (logger_) logger_->error("ConfigApply", "Invalid type for port." + id_str + ".admin_up"); }
                } else if (param == "mtu") {
                    if (auto* val_ptr = std::get_if<uint32_t>(&value)) { port_cfg.mtu = *val_ptr; config_changed = true; }
                     else if (auto* val_ptr_int = std::get_if<int>(&value)) { port_cfg.mtu = static_cast<uint32_t>(*val_ptr_int); config_changed = true; }
                    else { if (logger_) logger_->error("ConfigApply", "Invalid type for port." + id_str + ".mtu"); }
                }
                else {
                    if (logger_) logger_->warning("ConfigApply", "Unrecognized param " + param + " for port " + id_str);
                }

                if (config_changed) {
                    target_switch.interface_manager_.configure_port(port_id, port_cfg);
                    if (logger_) logger_->info("ConfigApply", "Applied port." + id_str + "." + param);
                }
            } else {
                 if (logger_) logger_->error("ConfigApply", "Invalid port ID " + id_str);
            }
        } else if (component == "vlan") {
            if (logger_) logger_->info("ConfigApply", "VLAN config for " + id_str + " (placeholder).");
        }
        else {
            if (logger_) logger_->warning("ConfigApply", "Unrecognized component " + component);
        }
    }
    if (logger_) logger_->info("ConfigApply", "Configuration application finished.");
}

} // namespace netflow
