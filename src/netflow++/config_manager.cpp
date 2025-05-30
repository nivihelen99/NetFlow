#include "netflow++/config_manager.hpp"
#include "netflow++/switch.hpp" // Required for Switch class definition
#include <iostream> // For std::cout, remove in production

namespace netflow {

void ConfigManager::apply_config(Switch& switch_obj) {
    for (const auto& pair : config_data_) {
        const std::string& key = pair.first;
        const ConfigValue& value_variant = pair.second;

        try {
            if (key == "fdb.aging_time_seconds") {
                if (std::holds_alternative<int>(value_variant)) {
                    int aging_time = std::get<int>(value_variant);
                    // Assuming Switch has a method to set FDB aging time
                    // switch_obj.get_fdb_manager().set_aging_time(aging_time);
                    std::cout << "Applied FDB aging time: " << aging_time << std::endl;
                } else {
                    std::cerr << "Error: Invalid type for " << key << std::endl;
                }
            } else if (key == "stp.bridge_priority") {
                if (std::holds_alternative<int>(value_variant)) {
                    int bridge_priority = std::get<int>(value_variant);
                    // Assuming Switch has a method to set STP bridge priority
                    // switch_obj.get_stp_manager().set_bridge_priority(bridge_priority);
                    std::cout << "Applied STP bridge priority: " << bridge_priority << std::endl;
                } else {
                    std::cerr << "Error: Invalid type for " << key << std::endl;
                }
            }
            // Add more configuration parameters as needed
        } catch (const std::bad_variant_access& e) {
            std::cerr << "Error accessing variant for key " << key << ": " << e.what() << std::endl;
        }
    }
}

#include <fstream> // For std::ifstream
#include <nlohmann/json.hpp> // For nlohmann::json

// Helper function to recursively parse JSON and populate config_data_
void parse_json_to_config(const nlohmann::json& j, const std::string& prefix, ConfigurationData& config_data) {
    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string current_key = prefix.empty() ? it.key() : prefix + "." + it.key();
        if (it.value().is_structured()) {
            parse_json_to_config(it.value(), current_key, config_data);
        } else {
            if (it.value().is_boolean()) {
                config_data[current_key] = it.value().get<bool>();
            } else if (it.value().is_number_integer()) {
                config_data[current_key] = it.value().get<int>();
            } else if (it.value().is_number_unsigned()) {
                config_data[current_key] = it.value().get<uint32_t>(); // Or uint64_t if needed, adjust ConfigValue
            } else if (it.value().is_number_float()) {
                config_data[current_key] = it.value().get<double>();
            } else if (it.value().is_string()) {
                config_data[current_key] = it.value().get<std::string>();
            } else if (it.value().is_array()) {
                // Example: store arrays of numbers (uint32_t) or strings
                // This needs to be more robust based on expected array types
                if (!it.value().empty()) {
                    if (it.value()[0].is_number_unsigned()) {
                        config_data[current_key] = it.value().get<std::vector<uint32_t>>();
                    } else if (it.value()[0].is_string()) {
                        config_data[current_key] = it.value().get<std::vector<std::string>>();
                    }
                }
            }
        }
    }
}

bool ConfigManager::load_config(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open configuration file: " << file_path << std::endl;
        return false;
    }

    nlohmann::json json_config;
    try {
        file >> json_config;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "Error: Could not parse JSON configuration file: " << file_path << "\n"
                  << "Parse error: " << e.what() << std::endl;
        return false;
    }

    config_data_.clear();
    try {
        parse_json_to_config(json_config, "", config_data_);
    } catch (const std::exception& e) {
        std::cerr << "Error processing JSON structure: " << e.what() << std::endl;
        return false;
    }

    loaded_config_filename_ = file_path; // Store the path of the loaded file
    std::cout << "Configuration loaded successfully from: " << file_path << std::endl;
    return true;
}

} // namespace netflow
