#ifndef NETFLOW_ISIS_COMMON_HPP
#define NETFLOW_ISIS_COMMON_HPP

#include <cstdint> // For uint8_t etc.
#include <vector>  // For std::vector
#include <array>   // For std::array

namespace netflow {
namespace isis {

// IS-IS Constants

// SystemID length
constexpr uint8_t SYSTEM_ID_LENGTH = 6;
// Max Area Addresses
constexpr uint8_t MAX_AREA_ADDRESSES = 3; // As per ISO 10589, but can be tuned

// Data Types

// SystemID type (6 bytes)
using SystemID = std::array<uint8_t, SYSTEM_ID_LENGTH>;

// AreaAddress type (variable length, up to 20 bytes including AFI and Area ID)
using AreaAddress = std::vector<uint8_t>;

// TLV (Type, Length, Value) Structure
struct Tlv {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> value;

    // Default constructor
    Tlv() : type(0), length(0) {}

    // Constructor with values
    Tlv(uint8_t t, const std::vector<uint8_t>& v) : type(t), length(static_cast<uint8_t>(v.size())), value(v) {}
    Tlv(uint8_t t, uint8_t l, const std::vector<uint8_t>& v) : type(t), length(l), value(v) {}
};

// Common PDU Header Structure (ISO 10589 - 8.1)
struct CommonPduHeader {
    uint8_t intradomain_routing_protocol_discriminator; // 0x83 for IS-IS
    uint8_t length_indicator;                           // Length of the PDU (including fixed header and TLVs)
    uint8_t version_protocol_id_extension;            // Currently 1 (0x01)
    uint8_t id_length;                                  // Length of NSAP ID (SystemID) part; 0 for 6 bytes, 255 for 0 bytes (null)
    uint8_t pdu_type_version_reserved;                  // Bits: RRR TTTTT (R=Reserved, T=PDU Type), followed by Version (next field)
    uint8_t version;                                    // Currently 1 (0x01)
    uint8_t reserved;                                   // Must be 0
    uint8_t max_area_addresses;                         // Max areas allowed in this system

    CommonPduHeader() :
        intradomain_routing_protocol_discriminator(0x83),
        length_indicator(0), // To be filled by specific PDU
        version_protocol_id_extension(0x01),
        id_length(0), // Indicates 6-byte SystemID. Set to 0xFF for no System ID.
        pdu_type_version_reserved(0), // PDU type part to be set by specific PDU
        version(0x01),
        reserved(0),
        max_area_addresses(MAX_AREA_ADDRESSES) {}
};

// PDU Type Constants (ISO 10589 - Table 5)
constexpr uint8_t L1_LAN_IIH_TYPE = 15;
constexpr uint8_t L2_LAN_IIH_TYPE = 16;
constexpr uint8_t PTP_IIH_TYPE    = 17;
constexpr uint8_t L1_LSP_TYPE     = 18;
constexpr uint8_t L2_LSP_TYPE     = 20;
constexpr uint8_t L1_CSNP_TYPE    = 24;
constexpr uint8_t L2_CSNP_TYPE    = 25;
constexpr uint8_t L1_PSNP_TYPE    = 26;
constexpr uint8_t L2_PSNP_TYPE    = 27;

// TLV Type Constants
// ISO 10589 Section 9.1
constexpr uint8_t AREA_ADDRESSES_TLV_TYPE           = 1;
constexpr uint8_t IS_NEIGHBORS_TLV_TYPE             = 2;
constexpr uint8_t ES_NEIGHBORS_TLV_TYPE             = 3;
constexpr uint8_t PARTITION_DISP_TLV_TYPE           = 4;
constexpr uint8_t PREFIX_NEIGHBORS_TLV_TYPE         = 5;
constexpr uint8_t PADDING_TLV_TYPE                  = 8;
constexpr uint8_t LSP_BUFFER_SIZE_TLV_TYPE          = 14;
constexpr uint8_t AUTHENTICATION_INFORMATION_TLV_TYPE = 10;

// RFC 1195 - IP specific TLVs
constexpr uint8_t IP_INTERNAL_REACH_TLV_TYPE      = 128;
constexpr uint8_t PROTOCOLS_SUPPORTED_TLV_TYPE    = 129;
constexpr uint8_t IP_EXTERNAL_REACH_TLV_TYPE      = 130;
constexpr uint8_t IP_INTERFACE_ADDRESS_TLV_TYPE   = 132;

// RFC 5305 - Extended Reachability TLVs
constexpr uint8_t EXTENDED_IS_REACHABILITY_TLV_TYPE = 22;
constexpr uint8_t EXTENDED_IP_REACHABILITY_TLV_TYPE = 135;

// Other common TLVs
constexpr uint8_t DYNAMIC_HOSTNAME_TLV_TYPE         = 137; // RFC 5301
constexpr uint8_t ROUTER_CAPABILITY_TLV_TYPE        = 242; // RFC 7981 (updates RFC 4971)
constexpr uint8_t PTP_ADJACENCY_THREE_WAY_TLV_TYPE  = 240; // RFC 5303 (For PTP IIH)

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_COMMON_HPP
