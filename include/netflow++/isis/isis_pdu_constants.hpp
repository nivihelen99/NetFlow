#ifndef ISIS_PDU_CONSTANTS_HPP
#define ISIS_PDU_CONSTANTS_HPP

#include <cstdint>

namespace netflow {
namespace isis {

// ISIS Protocol Discriminator
constexpr uint8_t ISIS_PROTOCOL_DISCRIMINATOR = 0x83;

// ISIS PDU Types
constexpr uint8_t ISIS_PDU_L1_LAN_IIH = 0x0F;  // Level-1 LAN IIH
constexpr uint8_t ISIS_PDU_L2_LAN_IIH = 0x10;  // Level-2 LAN IIH
constexpr uint8_t ISIS_PDU_PTP_IIH = 0x11;     // Point-to-Point IIH
constexpr uint8_t ISIS_PDU_L1_LSP = 0x12;      // Level-1 Link State PDU
constexpr uint8_t ISIS_PDU_L2_LSP = 0x14;      // Level-2 Link State PDU
constexpr uint8_t ISIS_PDU_L1_CSNP = 0x18;     // Level-1 Complete Sequence Numbers PDU
constexpr uint8_t ISIS_PDU_L2_CSNP = 0x19;     // Level-2 Complete Sequence Numbers PDU
constexpr uint8_t ISIS_PDU_L1_PSNP = 0x1A;     // Level-1 Partial Sequence Numbers PDU
constexpr uint8_t ISIS_PDU_L2_PSNP = 0x1B;     // Level-2 Partial Sequence Numbers PDU

// ISIS Version
constexpr uint8_t ISIS_VERSION = 0x01;

// ISIS System ID Length
constexpr uint8_t ISIS_SYSTEM_ID_LEN = 6;

// ISIS Area Address Lengths
constexpr uint8_t ISIS_MIN_AREA_ADDR_LEN = 1;
constexpr uint8_t ISIS_MAX_AREA_ADDR_LEN = 20;

// ISIS LSP Fragment ID Length
constexpr uint8_t ISIS_LSP_FRAGMENT_ID_LEN = 1;

// ISIS Pseudonode ID Length
constexpr uint8_t ISIS_PSEUDONODE_ID_LEN = 1;

// ISIS LSP ID Total Length (System ID + Pseudonode + Fragment)
constexpr uint8_t ISIS_LSP_ID_LEN = ISIS_SYSTEM_ID_LEN + ISIS_PSEUDONODE_ID_LEN + ISIS_LSP_FRAGMENT_ID_LEN;

// TLV Type Codes (RFC 1195, RFC 5305, RFC 5308, etc.)
constexpr uint8_t ISIS_TLV_AREA_ADDRESSES = 1;
constexpr uint8_t ISIS_TLV_IIS_NEIGHBORS = 2;
constexpr uint8_t ISIS_TLV_ES_NEIGHBORS = 3;
constexpr uint8_t ISIS_TLV_PART_DIS = 4;
constexpr uint8_t ISIS_TLV_PREFIX_NEIGHBORS = 5;
constexpr uint8_t ISIS_TLV_IIS_NEIGHBORS_VAR_LEN = 6;
constexpr uint8_t ISIS_TLV_PADDING = 8;
constexpr uint8_t ISIS_TLV_LSP_ENTRIES = 9;
constexpr uint8_t ISIS_TLV_AUTH_INFO = 10;
constexpr uint8_t ISIS_TLV_OPT_CHECKSUM = 12;
constexpr uint8_t ISIS_TLV_PURGE_ORIGINATOR = 13;
constexpr uint8_t ISIS_TLV_LSP_BUFFER_SIZE = 14;
constexpr uint8_t ISIS_TLV_EXT_IP_REACH = 130;
constexpr uint8_t ISIS_TLV_PROTOCOLS_SUPPORTED = 129;
constexpr uint8_t ISIS_TLV_IP_INT_REACH = 128;
constexpr uint8_t ISIS_TLV_TE_IS_NEIGHBORS = 22;
constexpr uint8_t ISIS_TLV_EXT_IS_REACH = 22;  // Same as TE_IS_NEIGHBORS
constexpr uint8_t ISIS_TLV_IS_ALIAS = 24;
constexpr uint8_t ISIS_TLV_IPV6_INT_REACH = 236;
constexpr uint8_t ISIS_TLV_MT_IS_NEIGHBORS = 222;
constexpr uint8_t ISIS_TLV_MT_IP_REACH = 235;
constexpr uint8_t ISIS_TLV_IPV6_REACH = 236;
constexpr uint8_t ISIS_TLV_RESTART = 211;
constexpr uint8_t ISIS_TLV_MT_SUPPORTED = 229;
constexpr uint8_t ISIS_TLV_HOSTNAME = 137;
constexpr uint8_t ISIS_TLV_TE_ROUTER_ID = 134;
constexpr uint8_t ISIS_TLV_SHARED_RISK_LINK_GROUP = 138;
constexpr uint8_t ISIS_TLV_IPV4_INTF_ADDR = 132;
constexpr uint8_t ISIS_TLV_IPV6_INTF_ADDR = 232;

// Sub-TLV Type Codes for Extended IS Reachability (TLV 22)
constexpr uint8_t ISIS_SUBTLV_ADMIN_GROUP = 3;
constexpr uint8_t ISIS_SUBTLV_IPV4_INTF_ADDR = 6;
constexpr uint8_t ISIS_SUBTLV_IPV4_NEIGHBOR_ADDR = 8;
constexpr uint8_t ISIS_SUBTLV_MAX_LINK_BANDWIDTH = 9;
constexpr uint8_t ISIS_SUBTLV_MAX_RESERVABLE_BANDWIDTH = 10;
constexpr uint8_t ISIS_SUBTLV_UNRESERVED_BANDWIDTH = 11;
constexpr uint8_t ISIS_SUBTLV_TE_DEFAULT_METRIC = 18;
constexpr uint8_t ISIS_SUBTLV_LINK_LOCAL_REMOTE_ID = 4;
constexpr uint8_t ISIS_SUBTLV_IPV6_INTF_ADDR = 12;
constexpr uint8_t ISIS_SUBTLV_IPV6_NEIGHBOR_ADDR = 13;

// Circuit Type Values
constexpr uint8_t ISIS_CIRCUIT_TYPE_RESERVED = 0;
constexpr uint8_t ISIS_CIRCUIT_TYPE_L1_ONLY = 1;
constexpr uint8_t ISIS_CIRCUIT_TYPE_L2_ONLY = 2;
constexpr uint8_t ISIS_CIRCUIT_TYPE_L1L2 = 3;

// Priority Values
constexpr uint8_t ISIS_PRIORITY_MIN = 0;
constexpr uint8_t ISIS_PRIORITY_MAX = 127;

// Holding Time Values
constexpr uint16_t ISIS_HOLDING_TIME_MIN = 1;
constexpr uint16_t ISIS_HOLDING_TIME_MAX = 65535;

// LSP Flags
constexpr uint8_t ISIS_LSP_FLAG_PARTITION_REPAIR = 0x80;
constexpr uint8_t ISIS_LSP_FLAG_ATTACHED_ERROR = 0x40;
constexpr uint8_t ISIS_LSP_FLAG_ATTACHED_EXPENSE = 0x20;
constexpr uint8_t ISIS_LSP_FLAG_ATTACHED_DELAY = 0x10;
constexpr uint8_t ISIS_LSP_FLAG_ATTACHED_DEFAULT = 0x08;
constexpr uint8_t ISIS_LSP_FLAG_OVERLOAD = 0x04;

// Authentication Types
constexpr uint8_t ISIS_AUTH_TYPE_CLEARTEXT = 1;
constexpr uint8_t ISIS_AUTH_TYPE_HMAC_MD5 = 54;
constexpr uint8_t ISIS_AUTH_TYPE_GENERIC_CRYPTO = 3;

// Metric Types
constexpr uint32_t ISIS_METRIC_INTERNAL = 0x00;
constexpr uint32_t ISIS_METRIC_EXTERNAL = 0x40;
constexpr uint32_t ISIS_METRIC_UNREACHABLE = 0x3F;
constexpr uint32_t ISIS_WIDE_METRIC_MAX = 0xFFFFFE;
constexpr uint32_t ISIS_WIDE_METRIC_UNREACHABLE = 0xFFFFFF;

// Multi-Topology IDs
constexpr uint16_t ISIS_MT_IPV4_UNICAST = 0;
constexpr uint16_t ISIS_MT_IPV6_UNICAST = 2;
constexpr uint16_t ISIS_MT_IPV4_MULTICAST = 3;
constexpr uint16_t ISIS_MT_IPV6_MULTICAST = 4;

// Protocol Supported Values
constexpr uint8_t ISIS_NLPID_IPV4 = 0xCC;
constexpr uint8_t ISIS_NLPID_IPV6 = 0x8E;

// Maximum Values
constexpr uint16_t ISIS_MAX_PDU_LEN = 1492;
constexpr uint16_t ISIS_MIN_PDU_LEN = 8;
constexpr uint8_t ISIS_MAX_TLV_LEN = 255;
constexpr uint16_t ISIS_MAX_LSP_SIZE = 1492;
constexpr uint32_t ISIS_MAX_SEQUENCE_NUMBER = 0xFFFFFFFF;

// Default Values
constexpr uint16_t ISIS_DEFAULT_LSP_LIFETIME = 1200;  // seconds
constexpr uint8_t ISIS_DEFAULT_PRIORITY = 64;
constexpr uint16_t ISIS_DEFAULT_HELLO_INTERVAL = 10;  // seconds
constexpr uint16_t ISIS_DEFAULT_HOLDING_TIME = 30;    // seconds
constexpr uint8_t ISIS_DEFAULT_CSNP_INTERVAL = 10;    // seconds

// Error Codes
constexpr int ISIS_SUCCESS = 0;
constexpr int ISIS_ERROR_INVALID_PDU = -1;
constexpr int ISIS_ERROR_INVALID_TLV = -2;
constexpr int ISIS_ERROR_BUFFER_TOO_SMALL = -3;
constexpr int ISIS_ERROR_INVALID_LENGTH = -4;
constexpr int ISIS_ERROR_CHECKSUM_FAILED = -5;
constexpr int ISIS_ERROR_AUTH_FAILED = -6;

} // namespace isis
} // namespace netflow

#endif // ISIS_PDU_CONSTANTS_HPP
