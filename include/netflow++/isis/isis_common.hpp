#ifndef NETFLOW_ISIS_COMMON_HPP
#define NETFLOW_ISIS_COMMON_HPP

#include <cstdint>
#include <vector>
#include <array>

namespace netflow {
namespace isis {

// SystemID type (6 bytes)
using SystemID = std::array<uint8_t, 6>;

// AreaAddress type (variable length)
using AreaAddress = std::vector<uint8_t>;

// TLV structure (Type, Length, Value)
struct TLV {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> value;
};

// Common PDU header structure
struct CommonPduHeader {
    uint8_t intradomainRoutingProtocolDiscriminator; // 0x83
    uint8_t lengthIndicator;
    uint8_t versionProtocolIdExtension; // 0x01
    uint8_t idLength; // SystemID length (0-8, 0 means 6 bytes)
    uint8_t pduType; // PDU Type (e.g., L1_LAN_IIH, L2_LSP)
    uint8_t version; // 0x01
    uint8_t reserved; // 0x00
    uint8_t maxAreaAddresses; // Maximum number of area addresses permitted
};

// Relevant PDU type constants
constexpr uint8_t L1_LAN_IIH_TYPE = 0x0F;
constexpr uint8_t L2_LAN_IIH_TYPE = 0x10;
constexpr uint8_t PTP_IIH_TYPE = 0x11;
constexpr uint8_t L1_LSP_TYPE = 0x12;
constexpr uint8_t L2_LSP_TYPE = 0x14;
constexpr uint8_t L1_CSNP_TYPE = 0x18;
constexpr uint8_t L2_CSNP_TYPE = 0x19;
constexpr uint8_t L1_PSNP_TYPE = 0x1A;
constexpr uint8_t L2_PSNP_TYPE = 0x1B;


// TLV type constants
constexpr uint8_t AREA_ADDRESSES_TLV_TYPE = 1;
constexpr uint8_t IS_NEIGHBORS_TLV_TYPE = 6; // For PTP IIH
constexpr uint8_t PADDING_TLV_TYPE = 8; // For IIH
constexpr uint8_t LSP_ENTRIES_TLV_TYPE = 9; // For CSNP/PSNP (deprecated by IETF) - this is a conceptual grouping, not an actual TLV type
constexpr uint8_t AUTHENTICATION_INFORMATION_TLV_TYPE = 10;
constexpr uint8_t IP_INTERNAL_REACH_TLV_TYPE = 128;
constexpr uint8_t PROTOCOLS_SUPPORTED_TLV_TYPE = 129;
constexpr uint8_t EXTENDED_IP_REACHABILITY_TLV_TYPE = 135;
constexpr uint8_t IS_ALIAS_ID_TLV_TYPE = 137; // For LSPs
constexpr uint8_t IS_NEIGHBOR_TLV_TYPE = 132; // For LAN IIH (ISIS SPB) / Not standard IS-IS, but often seen
                                        // Standard IS-IS uses TLV 6 for PTP IIH and TLV 2 for LAN IIH (IS Neighbors)
constexpr uint8_t IS_NEIGHBORS_LAN_TLV_TYPE = 2; // IS Neighbors for LAN Hello

// Multicast TLV Types (Experimental/Example Values - choose from private range or as per standard if adopted)
constexpr uint8_t MULTICAST_CAPABILITY_TLV_TYPE = 230;    // Indicates multicast routing capability
constexpr uint8_t MULTICAST_GROUP_MEMBERSHIP_TLV_TYPE = 231; // Advertises group memberships (e.g., (*,G) or (S,G))

// P2P Adjacency State TLV Type (RFC 5303)
constexpr uint8_t P2P_ADJACENCY_STATE_TLV_TYPE = 240;

// Standard IS Reachability TLV types
constexpr uint8_t ISIS_TLV_IS_REACHABILITY = 2; // Same as IS_NEIGHBORS_LAN_TLV_TYPE, commonly used for L1 IS Reachability
constexpr uint8_t ISIS_TLV_EXTENDED_IS_REACHABILITY = 22; // Standard for Extended IS Reachability

// Note: LSP_ENTRIES_TLV_TYPE is already defined above as 9.

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_COMMON_HPP
