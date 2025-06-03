#ifndef NETFLOW_ISIS_PDU_HPP
#define NETFLOW_ISIS_PDU_HPP

#include "isis_common.hpp"
#include <vector>
#include <cstdint>

namespace netflow {
namespace isis {

// --- TLV Value Structures ---

// Value for Area Addresses TLV (Type 1)
struct AreaAddressesTlvValue {
    std::vector<AreaAddress> areaAddresses;
};

// Value for IS Neighbors TLV (Type 6 for PTP IIH, Type 2 for LAN IIH)
// This TLV simply contains a list of SystemIDs of neighbors.
// For LAN IIH (Type 2), it's a list of 6-byte MAC addresses.
// For PTP IIH (Type 6), it's a list of 6-byte SystemIDs.
// We'll use a generic structure here.
struct IsNeighborsTlvValue {
    std::vector<std::array<uint8_t, 6>> neighbors; // Could be MACs or SystemIDs
};

// Structure for an IP address (prefix) and metric for TLVs 128 and 135
struct IpReachabilityInfo {
    uint32_t ipAddress; // IP Address
    uint32_t subnetMask; // Subnet Mask for TLV 128, Prefix Length for TLV 135
    uint32_t metric;
    // TLV 128 has: Default Metric (1 byte), Delay Metric (1 byte), Expense Metric (1 byte), Error Metric (1 byte)
    // We'll simplify to a single metric for now, or use a more complex structure if needed.
    // For TLV 135, the metric is 4 bytes.
};

// Value for IP Internal Reachability TLV (Type 128)
struct IpInternalReachTlvValue {
    std::vector<IpReachabilityInfo> reachabilityEntries;
};

// Value for Extended IP Reachability TLV (Type 135)
struct ExtendedIpReachabilityTlvValue {
    std::vector<IpReachabilityInfo> reachabilityEntries;
    // This TLV can also contain sub-TLVs for more detailed information.
    // std::vector<TLV> subTlvs; // Optional: for future extension
};


// --- PDU Structures ---

// LAN Hello PDU (Level 1 and Level 2)
struct LanHelloPdu {
    CommonPduHeader commonHeader;
    uint8_t circuitType; // Level 1 or Level 2
    SystemID sourceId;   // SystemID of the sending IS
    uint16_t holdingTime;
    // PDU Length is in commonHeader.lengthIndicator
    uint8_t priority;
    std::array<uint8_t, 7> lanId; // SystemID (6 bytes) + Pseudonode ID (1 byte)
    std::vector<TLV> tlvs;
};

// Point-to-Point Hello PDU
struct PointToPointHelloPdu {
    CommonPduHeader commonHeader;
    uint8_t circuitType; // Always 0x03 for PTP? Check standard. Usually indicates L1/L2 capability.
    SystemID sourceId;
    uint16_t holdingTime;
    // PDU Length is in commonHeader.lengthIndicator
    uint8_t localCircuitId;
    std::vector<TLV> tlvs;
};

// LSP ID structure
struct LspId {
    SystemID systemId;
    uint8_t pseudonodeIdOrLspNumber; // Pseudonode ID for L1/L2, LSP number for PTP
};

// Link State PDU (LSP)
struct LinkStatePdu {
    CommonPduHeader commonHeader; // pduType will be L1_LSP_TYPE or L2_LSP_TYPE
    // PDU Length is in commonHeader.lengthIndicator, but LSP itself has a length field too.
    uint16_t pduLengthLsp; // Length of the LSP itself, starting from Remaining Lifetime
    uint16_t remainingLifetime;
    LspId lspId;
    uint32_t sequenceNumber;
    uint16_t checksum;
    uint8_t pAttOlIsTypeBits; // P (Partition Repair), ATT (Attached), OL (Overload), IS Type (L1/L2)
    std::vector<TLV> tlvs;
};

// LSP Entry structure (for CSNP and PSNP)
struct LspEntry {
    uint16_t lifetime;
    LspId lspId;
    uint32_t sequenceNumber;
    uint16_t checksum;
};

// Complete Sequence Numbers PDU (CSNP)
struct CompleteSequenceNumbersPdu {
    CommonPduHeader commonHeader; // pduType will be L1_CSNP_TYPE or L2_CSNP_TYPE
    // PDU Length is in commonHeader.lengthIndicator
    SystemID sourceId; // SystemID + CircuitID (0 for non-broadcast)
    LspId startLspId;
    LspId endLspId;
    std::vector<TLV> tlvs; // Standard CSNPs use TLV type 9 (conceptually) for LSP Entries
                           // However, modern implementations might just list LspEntry structures directly
                           // or use other TLVs. For now, using TLVs is more flexible.
                           // If LSP entries are directly included, the structure would be:
                           // std::vector<LspEntry> lspEntries;
};

// Partial Sequence Numbers PDU (PSNP)
struct PartialSequenceNumbersPdu {
    CommonPduHeader commonHeader; // pduType will be L1_PSNP_TYPE or L2_PSNP_TYPE
    // PDU Length is in commonHeader.lengthIndicator
    SystemID sourceId; // SystemID + CircuitID (0 for non-broadcast)
    std::vector<TLV> tlvs; // Similar to CSNP, TLV type 9 (conceptually) or direct entries.
                           // std::vector<LspEntry> lspEntries;
};


// --- Multicast TLV Value Structures ---

// Value for Multicast Capability TLV (Type 230 as per isis_common.hpp example)
// For now, its presence indicates capability. Could have flags for specific features.
struct MulticastCapabilityTlvValue {
    // bool supports_source_specific_trees; // Example future extension
    // For this subtask, an empty struct is sufficient.
    // The TLV itself will have type=MULTICAST_CAPABILITY_TLV_TYPE and length=0.
};

// Information for a single multicast group (and optional source)
struct MulticastGroupAddressInfo {
    IpAddress group_address{}; // Multicast group address (e.g., 224.x.x.x - 239.x.x.x)
    IpAddress source_address{}; // Source address for (S,G) or 0.0.0.0 for (*,G)

    bool operator==(const MulticastGroupAddressInfo& other) const {
        return group_address == other.group_address && source_address == other.source_address;
    }
};

// Value for Multicast Group Membership TLV (Type 231 as per isis_common.hpp example)
struct MulticastGroupMembershipTlvValue {
    std::vector<MulticastGroupAddressInfo> groups{};
};


} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_PDU_HPP
