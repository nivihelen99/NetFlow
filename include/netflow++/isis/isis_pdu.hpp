#ifndef NETFLOW_ISIS_PDU_HPP
#define NETFLOW_ISIS_PDU_HPP

#include "isis_common.hpp" // Provides SystemID, Tlv, std::array, etc.
#include <vector>          // For std::vector
#include <cstdint>         // For uint8_t, uint16_t, uint32_t
#include <string>          // For std::string (e.g. LspId::to_string)
#include <numeric>         // For std::accumulate (if used for checksums)
#include <algorithm>       // For std::copy (if used)
// <array> is included by isis_common.hpp

namespace netflow {
namespace isis {

// --- TLV Value Structures ---

struct AreaAddressesTlvValue {
    std::vector<AreaAddress> area_addresses;
};

struct IsNeighborsTlvValue {
    std::vector<SystemID> neighbor_system_ids;
};

struct IpInternalReachabilityEntry {
    uint8_t default_metric;
    uint32_t ip_address;
    uint32_t ip_mask;

    IpInternalReachabilityEntry() : default_metric(0), ip_address(0), ip_mask(0) {}
};

struct IpInternalReachTlvValue {
    std::vector<IpInternalReachabilityEntry> entries;
};

struct ExtendedIpReachabilityEntry {
    uint32_t metric;
    uint8_t prefix_length;
    std::vector<uint8_t> prefix;
    std::vector<Tlv> sub_tlvs;

    ExtendedIpReachabilityEntry() : metric(0), prefix_length(0) {}
};

struct ExtendedIpReachabilityTlvValue {
    std::vector<ExtendedIpReachabilityEntry> entries;
};

struct ExtendedIsReachabilityNeighbor {
    SystemID neighbor_id;
    uint32_t metric;
    std::vector<Tlv> sub_tlvs;
};

struct ExtendedIsReachabilityTlvValue {
    std::vector<ExtendedIsReachabilityNeighbor> neighbors;
};

// Information for a single multicast group (and optional source)
// Potentially part of a Multicast Group Membership TLV value
struct MulticastGroupAddressInfo {
    IpAddress group_address{}; // Multicast group address (e.g., 224.x.x.x - 239.x.x.x)
                               // IpAddress is typically uint32_t from packet.hpp via isis_common.hpp
    IpAddress source_address{}; // Source address for (S,G) or 0.0.0.0 for (*,G)

    // Default constructor is fine.
    // Add comparison operators if it's used as a key in maps or in sets directly.
    bool operator==(const MulticastGroupAddressInfo& other) const {
        return group_address == other.group_address && source_address == other.source_address;
    }
    bool operator<(const MulticastGroupAddressInfo& other) const {
        if (group_address < other.group_address) return true;
        if (other.group_address < group_address) return false;
        return source_address < other.source_address;
    }
};


// --- PDU Structures ---

struct LanHelloPdu {
    uint8_t circuit_type;
    SystemID source_id;
    uint16_t holding_time;
    uint16_t pdu_length;
    uint8_t priority;
    std::array<uint8_t, SYSTEM_ID_LENGTH + 1> lan_id;
    std::vector<Tlv> tlvs;

    LanHelloPdu() : circuit_type(0), holding_time(0), pdu_length(0), priority(64) {
        source_id.fill(0);
        lan_id.fill(0);
    }
};

struct PtpHelloPdu {
    uint8_t circuit_type;
    SystemID source_id;
    uint16_t holding_time;
    uint16_t pdu_length;
    uint8_t local_circuit_id;
    std::vector<Tlv> tlvs;

    PtpHelloPdu() : circuit_type(0), holding_time(0), pdu_length(0), local_circuit_id(0) {
        source_id.fill(0);
    }
};

struct LspId {
    SystemID system_id;
    uint8_t pseudonode_id;
    uint8_t lsp_number;

    LspId() : pseudonode_id(0), lsp_number(0) {
        system_id.fill(0);
    }

    bool operator<(const LspId& other) const {
        if (system_id < other.system_id) return true;
        if (other.system_id < system_id) return false;
        if (pseudonode_id < other.pseudonode_id) return true;
        if (other.pseudonode_id < pseudonode_id) return false;
        return lsp_number < other.lsp_number;
    }

    bool operator==(const LspId& other) const {
        return system_id == other.system_id &&
               pseudonode_id == other.pseudonode_id &&
               lsp_number == other.lsp_number;
    }
    // std::string to_string() const; // Example: Implement in .cpp
};

struct Lsp {
    uint16_t pdu_length;
    uint16_t remaining_lifetime;
    LspId lsp_id;
    uint32_t sequence_number;
    uint16_t checksum;
    uint8_t p_bit : 1;
    uint8_t att_bits : 4;
    uint8_t ol_bit : 1;
    uint8_t is_type : 2;
    std::vector<Tlv> tlvs;

    Lsp() :
        pdu_length(0), remaining_lifetime(0), /* lsp_id default constructed */
        sequence_number(0), checksum(0),
        p_bit(0), att_bits(0), ol_bit(0), is_type(0) {}
};

struct LspEntry {
    uint16_t remaining_lifetime;
    LspId lsp_id;
    uint32_t sequence_number;
    uint16_t checksum;

    LspEntry() : remaining_lifetime(0), /* lsp_id default constructed */ sequence_number(0), checksum(0) {}
};

struct CsnPdu {
    uint16_t pdu_length;
    SystemID source_id;
    LspId start_lsp_id;
    LspId end_lsp_id;
    std::vector<LspEntry> lsp_entries;
    std::vector<Tlv> tlvs;

    CsnPdu() : pdu_length(0) {
        source_id.fill(0);
    }
};

struct PsnPdu {
    uint16_t pdu_length;
    SystemID source_id;
    std::vector<LspEntry> lsp_entries;
    std::vector<Tlv> tlvs;

    PsnPdu() : pdu_length(0) {
        source_id.fill(0);
    }
};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_PDU_HPP
