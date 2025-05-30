#ifndef NETFLOW_PLUS_PLUS_CORE_TYPES_HPP
#define NETFLOW_PLUS_PLUS_CORE_TYPES_HPP

#include <array>
#include <cstdint>
#include <string>
#include <sstream> // For ostringstream
#include <iomanip> // For std::setw and std::setfill

namespace netflow_plus_plus {
namespace core {

/**
 * @brief Represents a 6-byte MAC address.
 */
struct MacAddress {
    std::array<uint8_t, 6> address;

    /**
     * @brief Default constructor (initializes to zeros).
     */
    MacAddress() : address{} {} // Value-initialize to zeros

    /**
     * @brief Constructs a MacAddress from six byte values.
     */
    MacAddress(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6)
        : address{b1, b2, b3, b4, b5, b6} {}

    /**
     * @brief Constructs a MacAddress from an array of 6 bytes.
     */
    explicit MacAddress(const std::array<uint8_t, 6>& arr) : address(arr) {}

    /**
     * @brief Constructs a MacAddress from a string (e.g., "00:1A:2B:3C:4D:5E").
     *
     * @param mac_str The MAC address as a string.
     * @throws std::invalid_argument if the string format is incorrect.
     */
    explicit MacAddress(const std::string& mac_str) : address{} {
        if (mac_str.length() != 17) {
            throw std::invalid_argument("MAC address string must be 17 characters long (e.g., 00:1A:2B:3C:4D:5E)");
        }
        for (int i = 0; i < 6; ++i) {
            if (i > 0 && mac_str[i * 3 - 1] != ':') {
                throw std::invalid_argument("MAC address string parts must be separated by colons");
            }
            std::string byte_str = mac_str.substr(i * 3, 2);
            if (byte_str.length() != 2 || !std::isxdigit(byte_str[0]) || !std::isxdigit(byte_str[1])) {
                 throw std::invalid_argument("Invalid hexadecimal characters in MAC address string");
            }
            address[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }
    }

    /**
     * @brief Converts the MAC address to a string representation (e.g., "00:1A:2B:3C:4D:5E").
     * @return The string representation of the MAC address.
     */
    std::string toString() const {
        std::ostringstream oss;
        for (size_t i = 0; i < address.size(); ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(address[i]);
            if (i < address.size() - 1) {
                oss << ":";
            }
        }
        return oss.str();
    }

    /**
     * @brief Equality comparison operator.
     */
    bool operator==(const MacAddress& other) const {
        return address == other.address;
    }

    /**
     * @brief Inequality comparison operator.
     */
    bool operator!=(const MacAddress& other) const {
        return !(*this == other);
    }
};

} // namespace core
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_CORE_TYPES_HPP
