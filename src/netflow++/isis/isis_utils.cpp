#include "netflow++/isis/isis_utils.hpp"
#include "netflow++/byte_swap.hpp" // For htons, ntohs (though parsers here assume network order mostly)
#include <cstring> // For memcpy
#include <iostream> // For stub output

namespace netflow {
namespace isis {

// --- BufferReader Implementation ---
BufferReader::BufferReader(const std::vector<uint8_t>& vec) : data_ptr(vec.data()), size_(vec.size()), offset(0) {}
BufferReader::BufferReader(const uint8_t* data, size_t s) : data_ptr(data), size_(s), offset(0) {}

bool BufferReader::can_read(size_t num_bytes) const {
    return offset + num_bytes <= size_;
}

// --- Common Parsing Utility Implementations (Stubs) ---
bool parse_u8(BufferReader& reader, uint8_t& value) {
    if (!reader.can_read(1)) return false;
    value = reader.data_ptr[reader.offset++];
    return true;
}

bool parse_u16(BufferReader& reader, uint16_t& value) {
    if (!reader.can_read(2)) return false;
    // Assuming data is in network byte order, store as host order.
    value = (static_cast<uint16_t>(reader.data_ptr[reader.offset]) << 8) | reader.data_ptr[reader.offset + 1];
    reader.offset += 2;
    value = ntohs(value); // Convert to host order after assembling
    return true;
}

bool parse_u32(BufferReader& reader, uint32_t& value) {
    if (!reader.can_read(4)) return false;
    value = (static_cast<uint32_t>(reader.data_ptr[reader.offset]) << 24) |
            (static_cast<uint32_t>(reader.data_ptr[reader.offset + 1]) << 16) |
            (static_cast<uint32_t>(reader.data_ptr[reader.offset + 2]) << 8) |
            reader.data_ptr[reader.offset + 3];
    reader.offset += 4;
    value = ntohl(value); // Convert to host order after assembling
    return true;
}

bool parse_bytes(BufferReader& reader, uint8_t* buffer, size_t len) {
    if (!reader.can_read(len)) return false;
    std::memcpy(buffer, reader.data_ptr + reader.offset, len);
    reader.offset += len;
    return true;
}

bool parse_system_id(BufferReader& reader, SystemID& sys_id) {
    return parse_bytes(reader, sys_id.data(), sys_id.size());
}

bool parse_lsp_id(BufferReader& reader, LspId& lsp_id) {
    if (!parse_system_id(reader, lsp_id.systemId)) return false;
    return parse_u8(reader, lsp_id.pseudonodeIdOrLspNumber);
}

bool parse_common_pdu_header(BufferReader& reader, CommonPduHeader& header) {
    // std::cout << "STUB: parse_common_pdu_header called" << std::endl;
    if (!reader.can_read(1)) return false; // Need at least 1 byte for intradomainRoutingProtocolDiscriminator
    header.intradomainRoutingProtocolDiscriminator = reader.data_ptr[reader.offset];
    if (header.intradomainRoutingProtocolDiscriminator != 0x83) return false; // Not IS-IS
    reader.offset++;

    if (!reader.can_read(1)) return false;
    header.lengthIndicator = reader.data_ptr[reader.offset++];

    if (!reader.can_read(1)) return false;
    header.versionProtocolIdExtension = reader.data_ptr[reader.offset++];
    if (header.versionProtocolIdExtension != 1) return false; // Not ISO 9542

    if (!reader.can_read(1)) return false;
    header.version = reader.data_ptr[reader.offset++];
    if (header.version != 1) return false; // Not IS-IS version 1

    if (!reader.can_read(1)) return false;
    header.reserved = reader.data_ptr[reader.offset++];

    if (!reader.can_read(1)) return false;
    header.pduType = reader.data_ptr[reader.offset++];
    // pduType validation specific to context

    if (!reader.can_read(1)) return false;
    header.idLength = reader.data_ptr[reader.offset++];
    // idLength validation (0 for 6-byte sysid, or other values) specific to context

    if (!reader.can_read(1)) return false;
    header.maxAreaAddresses = reader.data_ptr[reader.offset++];
    return true;
}


// --- PDU-specific Parsing Function Stubs ---
bool parse_lan_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LanHelloPdu& pdu) {
    // std::cout << "STUB: parse_lan_hello_pdu called" << std::endl;
    pdu.commonHeader = common_header;
    // Actual parsing logic needed here
    return true;
}

bool parse_point_to_point_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PointToPointHelloPdu& pdu) {
    // std::cout << "STUB: parse_point_to_point_hello_pdu called" << std::endl;
    pdu.commonHeader = common_header;
    return true;
}

bool parse_link_state_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LinkStatePdu& pdu) {
    // std::cout << "STUB: parse_link_state_pdu called" << std::endl;
    pdu.commonHeader = common_header;
    // A real implementation would parse pdu.pduLength first from the body.
    if (pdu_data.size() >= sizeof(CommonPduHeader) + sizeof(uint16_t)) {
        uint16_t pdu_len_val_net;
        // Offset for pduLength is right after common header
        std::memcpy(&pdu_len_val_net, pdu_data.data() + sizeof(CommonPduHeader), sizeof(uint16_t));
        pdu.pduLength = ntohs(pdu_len_val_net);
    } else {
        return false;
    }
    return true;
}

bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, CompleteSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: parse_complete_sequence_numbers_pdu called" << std::endl;
    pdu.commonHeader = common_header;
    return true;
}

bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PartialSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: parse_partial_sequence_numbers_pdu called" << std::endl;
    pdu.commonHeader = common_header;
    return true;
}

// --- PDU Serialization Function Stubs ---
std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu) {
    // std::cout << "STUB: serialize_lan_hello_pdu called" << std::endl;
    std::vector<uint8_t> data; data.push_back(pdu.commonHeader.pduType); return data;
}

std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu) {
    // std::cout << "STUB: serialize_point_to_point_hello_pdu called" << std::endl;
    std::vector<uint8_t> data; data.push_back(pdu.commonHeader.pduType); return data;
}

std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu) {
    // std::cout << "STUB: serialize_link_state_pdu called" << std::endl;
    std::vector<uint8_t> data; data.push_back(pdu.commonHeader.pduType); return data;
}

std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: serialize_complete_sequence_numbers_pdu called" << std::endl;
    std::vector<uint8_t> data; data.push_back(pdu.commonHeader.pduType); return data;
}

std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu) {
    // std::cout << "STUB: serialize_partial_sequence_numbers_pdu called" << std::endl;
    std::vector<uint8_t> data; data.push_back(pdu.commonHeader.pduType); return data;
}

// --- TLV Value Serialization Function Stubs ---
std::vector<uint8_t> serialize_area_addresses_tlv_value(const AreaAddressesTlvValue& value) {
    // std::cout << "STUB: serialize_area_addresses_tlv_value called" << std::endl;
    return {};
}
std::vector<uint8_t> serialize_multicast_capability_tlv_value(const MulticastCapabilityTlvValue& value) {
    // std::cout << "STUB: serialize_multicast_capability_tlv_value called" << std::endl;
    return {};
}
std::vector<uint8_t> serialize_multicast_group_membership_tlv_value(const MulticastGroupMembershipTlvValue& value) {
    // std::cout << "STUB: serialize_multicast_group_membership_tlv_value called" << std::endl;
    return {};
}

// --- Static Helper Serialization Function Implementations ---
void serialize_u16(std::vector<uint8_t>& buffer, uint16_t value) {
    // Value is expected to be in host byte order, convert to network byte order for serialization.
    uint16_t value_net = htons(value);
    buffer.push_back(static_cast<uint8_t>(value_net >> 8));
    buffer.push_back(static_cast<uint8_t>(value_net & 0xFF));
}

void serialize_u32(std::vector<uint8_t>& buffer, uint32_t value) {
    uint32_t value_net = htonl(value);
    buffer.push_back(static_cast<uint8_t>(value_net >> 24));
    buffer.push_back(static_cast<uint8_t>(value_net >> 16));
    buffer.push_back(static_cast<uint8_t>(value_net >> 8));
    buffer.push_back(static_cast<uint8_t>(value_net & 0xFF));
}

void serialize_lsp_id(std::vector<uint8_t>& buffer, const LspId& id) {
    buffer.insert(buffer.end(), id.systemId.begin(), id.systemId.end());
    buffer.push_back(id.pseudonodeIdOrLspNumber);
}

} // namespace isis
} // namespace netflow
