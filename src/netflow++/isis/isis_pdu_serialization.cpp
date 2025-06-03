#include "netflow++/isis/isis_pdu_serialization.hpp"
#include "netflow++/byte_swap.hpp" // For htons/htonl if needed
#include <cstring> // For memcpy
#include <iostream> // For stub output

// TODO: Implement these serialization functions more completely.
// These stubs primarily satisfy the linker and basic structural checks.

namespace netflow {
namespace isis {

// --- PDU Serialization Function Stubs ---
std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu) {
    // std::cout << "STUB: serialize_lan_hello_pdu called" << std::endl;
    std::vector<uint8_t> data; /* TODO: Implement */
    data.push_back(pdu.commonHeader.pduType); // Example of accessing a field
    return data;
}

std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu) {
    // std::cout << "STUB: serialize_point_to_point_hello_pdu called" << std::endl;
    std::vector<uint8_t> data; /* TODO: Implement */ return data;
}

std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu) {
    // std::cout << "STUB: serialize_link_state_pdu called" << std::endl;
    std::vector<uint8_t> data; /* TODO: Implement */ return data;
}

std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: serialize_complete_sequence_numbers_pdu called" << std::endl;
    std::vector<uint8_t> data; /* TODO: Implement */ return data;
}

std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: serialize_partial_sequence_numbers_pdu called" << std::endl;
    std::vector<uint8_t> data; /* TODO: Implement */ return data;
}

// --- TLV Value Serialization Function Stubs ---
std::vector<uint8_t> serialize_area_addresses_tlv_value(const AreaAddressesTlvValue& value) {
    // std::cout << "STUB: serialize_area_addresses_tlv_value called" << std::endl;
    std::vector<uint8_t> data;
    for (const auto& area : value.areaAddresses) {
        data.push_back(static_cast<uint8_t>(area.size()));
        data.insert(data.end(), area.begin(), area.end());
    }
    return data;
}

std::vector<uint8_t> serialize_protocols_supported_tlv_value(const std::vector<uint8_t>& nlpids) {
    // std::cout << "STUB: serialize_protocols_supported_tlv_value called" << std::endl;
    return nlpids; // Value is just the list of NLPIDs
}

std::vector<uint8_t> serialize_ip_interface_address_tlv_value(const IpAddress& ip_address) {
    // std::cout << "STUB: serialize_ip_interface_address_tlv_value called" << std::endl;
    std::vector<uint8_t> data(4);
    uint32_t ip_net = htonl(ip_address); // Assuming IpAddress is uint32_t in host order
    std::memcpy(data.data(), &ip_net, sizeof(ip_net));
    return data;
}

std::vector<uint8_t> serialize_is_reach_tlv_value(/* params */) {
    // std::cout << "STUB: serialize_is_reach_tlv_value called" << std::endl;
    return {};
}

std::vector<uint8_t> serialize_ext_is_reach_tlv_value(/* params */) {
    // std::cout << "STUB: serialize_ext_is_reach_tlv_value called" << std::endl;
    return {};
}

std::vector<uint8_t> serialize_ext_ip_reach_tlv_value(/* params */) {
    // std::cout << "STUB: serialize_ext_ip_reach_tlv_value called" << std::endl;
    return {};
}


std::vector<uint8_t> serialize_multicast_capability_tlv_value(const MulticastCapabilityTlvValue& value) {
    // std::cout << "STUB: serialize_multicast_capability_tlv_value called" << std::endl;
    return {}; // Empty value for this TLV
}

std::vector<uint8_t> serialize_multicast_group_membership_tlv_value(const MulticastGroupMembershipTlvValue& value) {
    // std::cout << "STUB: serialize_multicast_group_membership_tlv_value called" << std::endl;
    std::vector<uint8_t> data;
    // Each group is 2x IpAddress (assuming 4 bytes each)
    // For (S,G), source IpAddress + group IpAddress
    // For (*,G), 0.0.0.0 + group IpAddress
    for (const auto& group_info : value.groups) {
        uint32_t group_addr_net = htonl(group_info.group_address);
        uint32_t source_addr_net = htonl(group_info.source_address);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&group_addr_net), reinterpret_cast<const uint8_t*>(&group_addr_net) + 4);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&source_addr_net), reinterpret_cast<const uint8_t*>(&source_addr_net) + 4);
    }
    return data;
}


} // namespace isis
} // namespace netflow
