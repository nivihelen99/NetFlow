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

#include <fstream>   // For std::ifstream, std::ofstream
#include <sstream>   // For std::stringstream
#include <algorithm> // For std::transform for case-insensitive string comparison
#include <limits>    // For std::numeric_limits

// Forward declaration for logger if it's to be used
// Forward declare Switch to break include cycle
namespace netflow {
    class Switch;
    class SwitchLogger; // Forward declare SwitchLogger
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
        if (logger_) {
            // Cast logger_ to void* for logging its address or a simple presence indicator
            std::stringstream ss;
            ss << "Attempting to load configuration from: " << filename << " (Logger present: " << (logger_ ? "yes" : "no") << ")";
            // This is a placeholder for actual logging call using logger_ methods if available
            // For example: logger_->info("ConfigManager", ss.str());
        }

        std::ifstream file(filename);
        if (!file.is_open()) {
            if (logger_) { /* logger_->error("ConfigManager", "Failed to open config file: " + filename); */ }
            return false;
        }

        config_data_.clear();
        std::string line;
        int line_num = 0;
        while (std::getline(file, line)) {
            line_num++;
            // Trim whitespace (simple trim for example)
            line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
            line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

            if (line.empty() || line[0] == '#') { // Skip empty lines or comments
                continue;
            }

            size_t delimiter_pos = line.find('=');
            if (delimiter_pos == std::string::npos) {
                if (logger_) { /* logger_->warn("ConfigManager", "Skipping malformed line (no '='): " + line + " in file " + filename + " at line " + std::to_string(line_num)); */ }
                continue;
            }

            std::string key = line.substr(0, delimiter_pos);
            std::string value_str = line.substr(delimiter_pos + 1);

            // Trim key and value
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value_str.erase(0, value_str.find_first_not_of(" \t"));
            value_str.erase(value_str.find_last_not_of(" \t") + 1);


            if (key.empty()) {
                 if (logger_) { /* logger_->warn("ConfigManager", "Skipping line with empty key in file " + filename + " at line " + std::to_string(line_num)); */ }
                continue;
            }

            ConfigValue parsed_value;
            std::string lower_value_str = value_str;
            std::transform(lower_value_str.begin(), lower_value_str.end(), lower_value_str.begin(), ::tolower);

            if (lower_value_str == "true") {
                parsed_value = true;
            } else if (lower_value_str == "false") {
                parsed_value = false;
            } else {
                // Try parsing as int
                int int_val;
                auto [ptr, ec] = std::from_chars(value_str.data(), value_str.data() + value_str.size(), int_val);
                if (ec == std::errc() && ptr == value_str.data() + value_str.size()) {
                    parsed_value = int_val;
                } else {
                    // Try parsing as uint64_t (for larger positive integers that might exceed int)
                    uint64_t uint64_val;
                    auto [ptr_u64, ec_u64] = std::from_chars(value_str.data(), value_str.data() + value_str.size(), uint64_val);
                    if (ec_u64 == std::errc() && ptr_u64 == value_str.data() + value_str.size()) {
                        // Check if it fits in uint32_t
                        if (uint64_val <= std::numeric_limits<uint32_t>::max()) {
                            parsed_value = static_cast<uint32_t>(uint64_val);
                        } else {
                            parsed_value = uint64_val;
                        }
                    } else {
                        // Try parsing as double
                        double double_val;
                        // std::from_chars for double is C++17, but might not be fully implemented everywhere
                        // Using stringstream as a fallback or primary for broader compatibility for double
                        std::stringstream ss_double(value_str);
                        ss_double >> double_val;
                        if (!ss_double.fail() && ss_double.eof()) {
                             parsed_value = double_val;
                        } else {
                             parsed_value = value_str; // Default to string
                        }
                    }
                }
            }
            config_data_[key] = parsed_value;
            if (logger_) { /* logger_->info("ConfigManager", "Loaded: " + key + " = [value of type...]"); */ }
        }

        loaded_config_filename_ = filename;
        if (logger_) { /* logger_->info("ConfigManager", "Successfully loaded configuration from " + filename); */ }
        return true;
    }

    bool save_config(const std::string& filename_param = "") const {
        const std::string& target_filename = filename_param.empty() ? loaded_config_filename_ : filename_param;
        if (target_filename.empty()) {
            if (logger_) { /* logger_->error("ConfigManager", "Save failed: No filename specified and no config previously loaded."); */ }
            return false;
        }

        std::ofstream file(target_filename);
        if (!file.is_open()) {
            if (logger_) { /* logger_->error("ConfigManager", "Failed to open file for saving: " + target_filename); */ }
            return false;
        }

        if (logger_) { /* logger_->info("ConfigManager", "Saving configuration to " + target_filename); */ }
        for (const auto& pair : config_data_) {
            std::string value_str;
            std::visit([&](const auto& val) {
                using T = std::decay_t<decltype(val)>;
                if constexpr (std::is_same_v<T, bool>) {
                    value_str = val ? "true" : "false";
                } else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t> || std::is_same_v<T, double>) {
                    value_str = std::to_string(val);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    value_str = val;
                } else if constexpr (std::is_same_v<T, std::vector<uint32_t>> || std::is_same_v<T, std::vector<std::string>>) {
                    // For this basic implementation, skip vectors or log a warning.
                    // A more complex implementation might serialize to comma-separated or JSON array string.
                    if (logger_) { /* logger_->warn("ConfigManager", "Skipping vector type for key '" + pair.first + "' during basic save."); */ }
                    value_str = "[vector data not saved in basic mode]"; // Placeholder
                }
            }, pair.second);

            if (!value_str.empty() && value_str != "[vector data not saved in basic mode]") { // Don't write if vector was skipped and we want to truly skip it
                 file << pair.first << "=" << value_str << "\n";
            }
        }

        if (logger_) { /* logger_->info("ConfigManager", "Successfully saved configuration to " + target_filename); */ }
        return true;
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

    void set_logger(SwitchLogger* logger) {
        logger_ = logger;
    }

private:
    ConfigurationData config_data_;
    std::string loaded_config_filename_; // Stores the name of the file last loaded from
    SwitchLogger* logger_ = nullptr;   // Optional: for logging internal errors/info

public: // Forward declare to allow Switch to be an argument to apply_config
    // class netflow::Switch; // This creates a circular dependency if Switch.hpp includes config_manager.hpp
    // Instead, include "switch.hpp" above. // No, forward declare Switch, define apply_config in .cpp

    // Declaration only. Definition moved to config_manager.cpp
    void apply_config(const ConfigurationData& config_data_to_apply, netflow::Switch& target_switch);

    std::vector<std::string> validate_config(const ConfigurationData& config_to_validate) const {
        std::vector<std::string> errors;
        if (logger_) { /* logger_->info("ConfigManager", "Starting configuration validation..."); */ }

        for (const auto& pair : config_to_validate) {
            const std::string& key = pair.first;
            const ConfigValue& value = pair.second;

            // Check 1: Key should not be empty
            if (key.empty()) {
                errors.push_back("Configuration key cannot be empty.");
                if (logger_) { /* logger_->error("ConfigManagerValidation", "Empty configuration key found."); */ }
            }

            // Check 2: Example: "port.X.speed_mbps" should be uint32_t or int
            // This is a simplified check. A real implementation would parse 'X' properly.
            if (key.rfind(".speed_mbps", 0) == 0 || (key.find("port.") == 0 && key.rfind(".speed_mbps") != std::string::npos)) {
                // Check if the part before ".speed_mbps" is like "port.X"
                size_t port_prefix_len = std::string("port.").length();
                size_t speed_suffix_pos = key.rfind(".speed_mbps");
                if (key.rfind("port.",0) == 0 && speed_suffix_pos != std::string::npos && speed_suffix_pos > port_prefix_len) {
                    std::string port_index_str = key.substr(port_prefix_len, speed_suffix_pos - port_prefix_len);
                    // Could further validate if port_index_str is a number here.

                    if (!std::holds_alternative<uint32_t>(value) && !std::holds_alternative<int>(value)) {
                        std::string err_msg = "Invalid type for key '" + key + "'. Expected uint32_t or int for speed_mbps.";
                        errors.push_back(err_msg);
                        if (logger_) { /* logger_->error("ConfigManagerValidation", err_msg); */ }
                    }
                }
            }
             // Add more checks as needed...
        }

        if (logger_) {
            if (!errors.empty()) {
                /* logger_->warn("ConfigManager", "Configuration validation found " + std::to_string(errors.size()) + " errors."); */
            } else {
                /* logger_->info("ConfigManager", "Configuration validation successful."); */
            }
        }
        return errors;
    }
};

} // namespace netflow

#endif // NETFLOW_CONFIG_MANAGER_HPP
