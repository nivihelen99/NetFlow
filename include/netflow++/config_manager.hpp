#ifndef NETFLOW_CONFIG_MANAGER_HPP
#define NETFLOW_CONFIG_MANAGER_HPP

#include <cstdint> // For uint32_t, uint64_t
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <stdexcept> // For std::bad_variant_access
#include <iostream>  // For placeholder error reporting
#include <charconv>  // For std::from_chars (C++17 for string to number)

// Forward declaration for logger if it's to be used
// Forward declare Switch to break include cycle
namespace netflow {
    class Switch;
}
// namespace netflow { class SwitchLogger; }

namespace netflow {

// Define supported configuration value types
using ConfigValue = std::variant<
    bool,
    int,
    uint32_t,
    uint64_t,
    double,
    std::string,
    std::vector<uint32_t>,
    std::vector<std::string>
    // Potentially add std::vector<bool>, std::vector<int>, etc. if needed
>;

// Configuration data is stored as a map of string paths to ConfigValue
using ConfigurationData = std::map<std::string, ConfigValue>;

class ConfigManager {
public:
    ConfigManager() = default;

    // Placeholder: Actual loading from a structured file format (e.g., JSON, YAML, INI)
    // would involve using a parsing library.
    // For now, it can be a no-op or load some hardcoded defaults.
    bool load_config(const std::string& filename) {
        // TODO: Implement file parsing (e.g., JSON using nlohmann/json or similar).
        //       This would involve opening the file, reading its content,
        //       parsing the structured data, and populating config_data_.

        // Example of loading hardcoded defaults:
        config_data_.clear(); // Clear any existing configuration
        // config_data_["global.hostname"] = std::string("NetFlowSwitch-Default");
        // config_data_["port.0.speed"] = static_cast<uint32_t>(1000);
        // config_data_["port.0.admin_up"] = true;
        // config_data_["features.stp.enabled"] = true;
        // config_data_["features.qos.default_queues"] = static_cast<uint32_t>(4);
        // config_data_["logging.default_level"] = std::string("INFO");

        loaded_config_filename_ = filename; // Store for potential save operation

        // if (logger_) logger_->info("CONFIG", "Configuration loaded from (placeholder) " + filename);
        return true; // Placeholder: always succeeds for now
    }

    // Placeholder: Actual saving to a structured file format would involve serialization.
    bool save_config(const std::string& filename_param = "") const {
        // TODO: Implement file serialization (e.g., to JSON).
        //       This would involve iterating through config_data_, converting
        //       ConfigValue variants to a serializable format, and writing to the file.

        const std::string& target_filename = filename_param.empty() ? loaded_config_filename_ : filename_param;
        if (target_filename.empty()) {
            // if (logger_) logger_->error("CONFIG", "Save failed: No filename specified and no config previously loaded.");
            return false; // No filename to save to
        }

        // Actual save logic would go here.
        // if (logger_) logger_->info("CONFIG", "Configuration saved to (placeholder) " + target_filename);
        return true; // Placeholder: always succeeds for now
    }

    // Retrieves a configuration parameter by its path (e.g., "port.1.speed").
    std::optional<ConfigValue> get_parameter(const std::string& path) const {
        auto it = config_data_.find(path);
        if (it != config_data_.end()) {
            return it->second;
        }
        // if (logger_) logger_->debug("CONFIG", "Parameter not found: " + path);
        return std::nullopt;
    }

    // Template helper to get a parameter and cast it to a specific type.
    template<typename T>
    std::optional<T> get_parameter_as(const std::string& path) const {
        std::optional<ConfigValue> opt_val = get_parameter(path);
        if (opt_val.has_value()) {
            try {
                // Check if the variant holds the requested type T
                if (std::holds_alternative<T>(opt_val.value())) {
                    return std::get<T>(opt_val.value());
                } else {
                    // Type mismatch, variant holds a different type than requested T
                    // if (logger_) logger_->warning("CONFIG", "Type mismatch for parameter: " + path + ". Requested type does not match stored type.");
                    return std::nullopt;
                }
            } catch (const std::bad_variant_access& ex) {
                // This catch block might be redundant if std::holds_alternative is used first,
                // but kept for robustness or if holds_alternative is removed.
                // if (logger_) logger_->error("CONFIG", "Bad variant access for parameter: " + path + ". Exception: " + ex.what());
                return std::nullopt;
            }
        }
        return std::nullopt; // Parameter not found
    }

    // Sets a configuration parameter.
    void set_parameter(const std::string& path, ConfigValue value) {
        // if (logger_) logger_->debug("CONFIG", "Setting parameter: " + path);
        config_data_[path] = value;
    }

    // Retrieves the entire current configuration data map (e.g., for inspection or saving).
    const ConfigurationData& get_current_config_data() const {
        return config_data_;
    }

    // void set_logger(SwitchLogger* logger) {
    //     logger_ = logger;
    // }

private:
    ConfigurationData config_data_;
    std::string loaded_config_filename_; // Stores the name of the file last loaded from
    // SwitchLogger* logger_ = nullptr;   // Optional: for logging internal errors/info

public: // Forward declare to allow Switch to be an argument to apply_config
    // class netflow::Switch; // This creates a circular dependency if Switch.hpp includes config_manager.hpp
    // Instead, include "switch.hpp" above. // No, forward declare Switch, define apply_config in .cpp

    // Declaration only. Definition moved to config_manager.cpp
    void apply_config(const ConfigurationData& config_data_to_apply, netflow::Switch& target_switch);

    std::vector<std::string> validate_config(const ConfigurationData& config_to_validate) const {
        std::vector<std::string> errors;
        // TODO: Implement detailed validation logic.
        // Examples:
        // - Check if paths are well-formed and recognized.
        // - Check if value types match expected types for parameters.
        // - Check if numerical values are within valid ranges.
        // - Check for dependencies (e.g., port must exist before setting its speed).
        // for (const auto& pair : config_to_validate) {
        //    const std::string& path = pair.first;
        //    const ConfigValue& value = pair.second;
        //    if (path == "port.X.speed" && !std::holds_alternative<uint32_t>(value)) {
        //        errors.push_back("Invalid type for " + path + ", expected uint32_t.");
        //    }
        // }
        // if (logger_ && !errors.empty()) logger_->warning("CONFIG_VALIDATE", std::to_string(errors.size()) + " validation errors found.");
        // else if (logger_) logger_->info("CONFIG_VALIDATE", "Configuration validation successful (placeholder).");
        return errors; // Return empty vector (no errors) for now
    }
};

} // namespace netflow

#endif // NETFLOW_CONFIG_MANAGER_HPP
