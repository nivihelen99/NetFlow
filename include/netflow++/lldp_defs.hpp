#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <array>
#include <algorithm> // For std::copy

// Forward declaration for MacAddress if it's defined elsewhere
// For now, let's assume it's a type alias or a struct defined in this project.
// If not, std::array<uint8_t, 6> will be used directly.
// namespace netflow {
// struct MacAddress;
// }


namespace netflow {

// LLDP Constants
constexpr uint16_t LLDP_ETHERTYPE = 0x88CC;
const std::array<uint8_t, 6> LLDP_MULTICAST_MAC = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};

// TLV Types
constexpr uint8_t TLV_TYPE_END_OF_LLDPDU = 0;
constexpr uint8_t TLV_TYPE_CHASSIS_ID = 1;
constexpr uint8_t TLV_TYPE_PORT_ID = 2;
constexpr uint8_t TLV_TYPE_TTL = 3;
constexpr uint8_t TLV_TYPE_PORT_DESCRIPTION = 4;
constexpr uint8_t TLV_TYPE_SYSTEM_NAME = 5;
constexpr uint8_t TLV_TYPE_SYSTEM_DESCRIPTION = 6;
// TLV_TYPE_SYSTEM_CAPABILITIES = 7 - Not requested but common
constexpr uint8_t TLV_TYPE_MANAGEMENT_ADDRESS = 8;
// TLV_TYPE_ORGANIZATION_SPECIFIC = 127 - Not requested but common

// Chassis ID Subtypes
constexpr uint8_t CHASSIS_ID_SUBTYPE_CHASSIS_COMPONENT = 1; // Not requested but common
constexpr uint8_t CHASSIS_ID_SUBTYPE_INTERFACE_ALIAS = 2; // Not requested but common
constexpr uint8_t CHASSIS_ID_SUBTYPE_PORT_COMPONENT = 3; // Not requested but common
constexpr uint8_t CHASSIS_ID_SUBTYPE_MAC_ADDRESS = 4;
constexpr uint8_t CHASSIS_ID_SUBTYPE_NETWORK_ADDRESS = 5; // Not requested but common
constexpr uint8_t CHASSIS_ID_SUBTYPE_INTERFACE_NAME = 6; // Not requested but common
constexpr uint8_t CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED = 7; // Not requested but common


// Port ID Subtypes
constexpr uint8_t PORT_ID_SUBTYPE_INTERFACE_ALIAS = 1;
constexpr uint8_t PORT_ID_SUBTYPE_PORT_COMPONENT = 2;
constexpr uint8_t PORT_ID_SUBTYPE_MAC_ADDRESS = 3;
constexpr uint8_t PORT_ID_SUBTYPE_NETWORK_ADDRESS = 4;
constexpr uint8_t PORT_ID_SUBTYPE_INTERFACE_NAME = 5;
constexpr uint8_t PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID = 6;
constexpr uint8_t PORT_ID_SUBTYPE_LOCALLY_ASSIGNED = 7;

// Basic TLV Structure
#pragma pack(push, 1) // Ensure packed structure
struct LldpTlvHeader {
    uint16_t type_length; // 7 bits for type, 9 bits for length

    // Helper to get TLV type (most significant 7 bits)
    uint8_t getType() const {
        return (type_length & 0xFE00) >> 9; // Mask is 11111110 00000000
    }

    // Helper to set TLV type
    void setType(uint8_t type) {
        type_length = (type_length & 0x01FF) | (static_cast<uint16_t>(type) << 9);
    }

    // Helper to get TLV length (least significant 9 bits)
    uint16_t getLength() const {
        return type_length & 0x01FF; // Mask is 00000001 11111111
    }

    // Helper to set TLV length
    void setLength(uint16_t length) {
        type_length = (type_length & 0xFE00) | (length & 0x01FF);
    }
};
#pragma pack(pop)

// Specific TLV Value Structures (Illustrative)
// These structures represent the value part of a TLV.
// The actual data will be parsed based on the length in LldpTlvHeader.

struct ChassisIdTlvValue {
    uint8_t subtype;
    std::vector<uint8_t> id; // For MAC address, this could be std::array<uint8_t, 6>
                             // but vector is more generic for other subtypes.
    // Example for MAC address specific usage:
    // std::array<uint8_t, 6> mac_address;
    // if (subtype == CHASSIS_ID_SUBTYPE_MAC_ADDRESS) { ... }
};

struct PortIdTlvValue {
    uint8_t subtype;
    std::vector<uint8_t> id;
};

struct TtlTlvValue {
    uint16_t seconds; // Time to Live in seconds
};

// LLDP Neighbor Structure
struct LldpNeighborInfo {
    uint8_t chassis_id_subtype;
    std::vector<uint8_t> chassis_id_raw; // Store raw ID bytes
    std::string chassis_id_str;          // Store string representation (e.g. MAC as hex)

    uint8_t port_id_subtype;
    std::vector<uint8_t> port_id_raw;   // Store raw ID bytes
    std::string port_id_str;            // Store string representation

    uint16_t ttl;

    std::string system_name;        // Optional
    std::string system_description; // Optional
    std::string port_description;   // Optional
    std::string management_address; // Optional, could be more complex (e.g. dedicated struct)

    std::chrono::steady_clock::time_point last_updated;
    uint32_t ingress_port; // e.g. SNMP ifIndex or similar local identifier

    // Helper to get chassis ID as string (e.g. for MAC address)
    std::string getChassisIdString() const {
        if (chassis_id_subtype == CHASSIS_ID_SUBTYPE_MAC_ADDRESS && chassis_id_raw.size() == 6) {
            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     chassis_id_raw[0], chassis_id_raw[1], chassis_id_raw[2],
                     chassis_id_raw[3], chassis_id_raw[4], chassis_id_raw[5]);
            return std::string(buf);
        }
        // For other subtypes or if not a MAC, return as is or based on subtype formatting
        return std::string(chassis_id_raw.begin(), chassis_id_raw.end());
    }

    // Helper to get port ID as string
     std::string getPortIdString() const {
        if (port_id_subtype == PORT_ID_SUBTYPE_MAC_ADDRESS && port_id_raw.size() == 6) {
            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     port_id_raw[0], port_id_raw[1], port_id_raw[2],
                     port_id_raw[3], port_id_raw[4], port_id_raw[5]);
            return std::string(buf);
        }
        // For Interface Name, Alias, Locally Assigned, etc. it's often just a string
        if (port_id_subtype == PORT_ID_SUBTYPE_INTERFACE_ALIAS ||
            port_id_subtype == PORT_ID_SUBTYPE_INTERFACE_NAME ||
            port_id_subtype == PORT_ID_SUBTYPE_LOCALLY_ASSIGNED ||
            port_id_subtype == PORT_ID_SUBTYPE_PORT_DESCRIPTION) { // Port description is not a port ID subtype but often string
             return std::string(port_id_raw.begin(), port_id_raw.end());
        }
        // For other subtypes, return raw bytes as a simple string or implement specific formatting
        return std::string(port_id_raw.begin(), port_id_raw.end());
    }
};

} // namespace netflow
