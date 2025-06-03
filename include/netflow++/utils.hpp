#ifndef NETFLOW_UTILS_HPP
#define NETFLOW_UTILS_HPP

#include <string>    // For std::string
#include <optional>  // For std::optional
#include <stdexcept> // For std::invalid_argument, std::out_of_range (used in .cpp)
#include <vector>    // For std::vector
#include <set>       // For std::set (potentially in .cpp)
#include <sstream>   // For std::stringstream
#include <iomanip>   // For std::hex, std::setfill, std::setw
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
std::vector<uint16_t> parse_vlan_list(const std::string& vlan_list_str);

// Helper to convert byte array (like SystemID or AreaAddress) to hex string with delimiter
template <typename TContainer>
std::string to_hex_string(const TContainer& container, char delimiter = '\0') {
    std::stringstream ss;
    bool first = true;
    for (const auto& byte_val : container) { // Renamed 'byte' to 'byte_val' to avoid potential macro conflicts
        if (!first && delimiter != '\0') {
            ss << delimiter;
        }
        // Ensure byte_val is treated as an unsigned char before casting to int for output,
        // to prevent sign extension if TContainer::value_type is char.
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(static_cast<uint8_t>(byte_val));
        first = false;
    }
    return ss.str();
}

} // namespace utils
} // namespace netflow

#endif // NETFLOW_UTILS_HPP
