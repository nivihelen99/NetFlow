#ifndef NETFLOW_ISIS_UTILS_HPP
#define NETFLOW_ISIS_UTILS_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp" // For PDU struct declarations
#include <vector>
#include <cstdint>
#include <string> // Required for memcpy with some compilers, though cstring is better
#include <cstring> // For memcpy

namespace netflow {
namespace isis {

// BufferReader struct definition
struct BufferReader {
    const uint8_t* data_ptr;
    size_t size_;
    size_t offset;

    BufferReader(const std::vector<uint8_t>& vec);
    BufferReader(const uint8_t* data, size_t s);

    bool can_read(size_t num_bytes) const;
};

// Common parsing utility declarations
bool parse_u8(BufferReader& reader, uint8_t& value);
bool parse_u16(BufferReader& reader, uint16_t& value);
bool parse_u32(BufferReader& reader, uint32_t& value);
bool parse_bytes(BufferReader& reader, uint8_t* buffer, size_t len);
bool parse_system_id(BufferReader& reader, SystemID& sys_id);
bool parse_lsp_id(BufferReader& reader, LspId& lsp_id);
bool parse_common_pdu_header(BufferReader& reader, CommonPduHeader& header);

// PDU-specific parsing function declarations
bool parse_lan_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LanHelloPdu& pdu);
bool parse_point_to_point_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PointToPointHelloPdu& pdu);
bool parse_link_state_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LinkStatePdu& pdu);
bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, CompleteSequenceNumbersPdu& pdu);
bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PartialSequenceNumbersPdu& pdu);

// PDU serialization function declarations
std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu);
std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu);
std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu);
std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu);
std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu);

// TLV value serialization function declarations
std::vector<uint8_t> serialize_area_addresses_tlv_value(const AreaAddressesTlvValue& value);
std::vector<uint8_t> serialize_multicast_capability_tlv_value(const MulticastCapabilityTlvValue& value);
std::vector<uint8_t> serialize_multicast_group_membership_tlv_value(const MulticastGroupMembershipTlvValue& value);

// Helper static serialization functions (often used by PDU/TLV serializers)
// These might be better as static members of a PduSerializer class or remain free static functions in the .cpp
// For now, declaring them to be defined in isis_utils.cpp
void serialize_u16(std::vector<uint8_t>& buffer, uint16_t value);
void serialize_u32(std::vector<uint8_t>& buffer, uint32_t value);
void serialize_lsp_id(std::vector<uint8_t>& buffer, const LspId& id);

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_UTILS_HPP
