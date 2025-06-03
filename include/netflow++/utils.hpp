#ifndef NETFLOW_UTILS_HPP
#define NETFLOW_UTILS_HPP

#include <string>
#include <optional>  // For std::optional (requires C++17 or a library version)
#include <stdexcept> // For std::invalid_argument, std::out_of_range
#include <vector>    // For parse_vlan_list
#include <set>       // For parse_vlan_list
#include <sstream>   // For parse_vlan_list
#include <iomanip>   // For std::setfill, std::setw
#include <cstdint>   // For uint16_t, uint8_t

namespace netflow {
namespace utils {

// Safely converts a string to an unsigned long.
// Returns std::nullopt if conversion fails.
std::optional<unsigned long> safe_stoul(const std::string& str);

// Safely converts a string to an int.
// Returns std::nullopt if conversion fails.
std::optional<int> safe_stoi(const std::string& str);

// Helper to parse VLAN lists like "10,20,30-35"
// This was seen in ManagementService.cpp, good to centralize if used elsewhere.
std::vector<uint16_t> parse_vlan_list(const std::string& vlan_list_str);

// Helper to convert byte array (like SystemID or AreaAddress) to hex string with delimiter
template <typename TContainer>
std::string to_hex_string(const TContainer& container, char delimiter = '\0') {
    std::stringstream ss;
    bool first = true;
    for (const auto& byte : container) {
        if (!first && delimiter != '\0') {
            ss << delimiter;
        }
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(static_cast<uint8_t>(byte));
        first = false;
    }
    return ss.str();
}


} // namespace utils
} // namespace netflow

#endif // NETFLOW_UTILS_HPP
