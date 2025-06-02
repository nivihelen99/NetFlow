#include "netflow++/utils.hpp"
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <stdexcept> // For std::stoul, std::stoi exceptions
#include <algorithm> // For std::remove in parse_vlan_list (if used that way)

// Note: to_hex_string is a template function and its definition should remain in utils.hpp

namespace netflow {
namespace utils {

std::optional<unsigned long> safe_stoul(const std::string& str) {
    try {
        size_t processed_chars = 0;
        unsigned long val = std::stoul(str, &processed_chars, 0); // 0 for auto-base detection (e.g. 0x for hex)
        if (processed_chars != str.length()) { // Ensure the entire string was consumed
            return std::nullopt; // Or handle as error: trailing characters
        }
        return val;
    } catch (const std::invalid_argument& ia) {
        // Log error or handle if necessary
        return std::nullopt;
    } catch (const std::out_of_range& oor) {
        // Log error or handle if necessary
        return std::nullopt;
    }
}

std::optional<int> safe_stoi(const std::string& str) {
    try {
        size_t processed_chars = 0;
        int val = std::stoi(str, &processed_chars, 0); // 0 for auto-base detection
        if (processed_chars != str.length()) { // Ensure the entire string was consumed
            return std::nullopt;
        }
        return val;
    } catch (const std::invalid_argument& ia) {
        return std::nullopt;
    } catch (const std::out_of_range& oor) {
        return std::nullopt;
    }
}

// Implementation of parse_vlan_list
// Parses strings like "10,20,30-35,40" into a vector of uint16_t
std::vector<uint16_t> parse_vlan_list(const std::string& vlan_list_str) {
    std::set<uint16_t> vlan_set; // Use set to handle duplicates and ordering naturally
    std::stringstream ss(vlan_list_str);
    std::string segment;

    while (std::getline(ss, segment, ',')) {
        segment.erase(std::remove_if(segment.begin(), segment.end(), ::isspace), segment.end()); // Remove whitespace
        if (segment.empty()) continue;

        size_t dash_pos = segment.find('-');
        if (dash_pos != std::string::npos) { // Range found
            std::string start_str = segment.substr(0, dash_pos);
            std::string end_str = segment.substr(dash_pos + 1);
            
            std::optional<unsigned long> start_opt = safe_stoul(start_str);
            std::optional<unsigned long> end_opt = safe_stoul(end_str);

            if (start_opt && end_opt && *start_opt <= *end_opt && *start_opt >= 1 && *end_opt <= 4094) {
                for (unsigned long i = *start_opt; i <= *end_opt; ++i) {
                    vlan_set.insert(static_cast<uint16_t>(i));
                }
            } else {
                throw std::runtime_error("Invalid VLAN range: " + segment);
            }
        } else { // Single VLAN ID
            std::optional<unsigned long> vlan_id_opt = safe_stoul(segment);
            if (vlan_id_opt && *vlan_id_opt >= 1 && *vlan_id_opt <= 4094) {
                vlan_set.insert(static_cast<uint16_t>(*vlan_id_opt));
            } else {
                 throw std::runtime_error("Invalid VLAN ID: " + segment);
            }
        }
    }
    return std::vector<uint16_t>(vlan_set.begin(), vlan_set.end());
}


} // namespace utils
} // namespace netflow
