#include "netflow++/isis/isis_pdu_parsing.hpp"
#include "netflow++/isis/isis_utils.hpp"    // For BufferReader and parse_u8, parse_system_id etc.
#include "netflow++/byte_swap.hpp" // For ntohs/ntohl if needed during parsing of multi-byte fields
#include <cstring> // For memcpy

// TODO: Implement these parsing functions more completely.
// These stubs primarily satisfy the linker and basic structural checks.

namespace netflow {
namespace isis {

// CommonPduHeader is parsed by a utility in isis_utils.cpp
// bool parse_common_pdu_header(BufferReader& reader, CommonPduHeader& header);

bool parse_lan_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LanHelloPdu& pdu) {
    pdu.commonHeader = common_header;
    BufferReader reader(pdu_data.data() + sizeof(CommonPduHeader), pdu_data.size() - sizeof(CommonPduHeader));

    if (!reader.can_read(1 + 6 + 2 + 2 + 1 + 7)) return false; // Minimum size for fixed fields after common header

    if (!parse_u8(reader, pdu.circuitType)) return false;
    if (!parse_system_id(reader, pdu.sourceId)) return false;
    if (!parse_u16(reader, pdu.holdingTime)) return false; // Already network byte order, parser should handle if needed
    // pdu.pduLength is tricky, it's the length of the PDU *from the byte after common header*.
    // This should have been parsed by a top-level PDU parser or set from common_header.lengthIndicator.
    // For now, the common_header.lengthIndicator might be the full PDU length.
    // This field in LanHelloPdu struct might be redundant if commonHeader.lengthIndicator is used.
    // Let's assume pdu.pduLength is set correctly if it were a real parser. Here, it's not used by the stub.
    if (!parse_u16(reader, pdu.pduLength)) return false; // This is the PDU length in the LanHelloPdu itself.
                                                       // It should match overall PDU length.

    if (!parse_u8(reader, pdu.priority)) return false;
    if (!parse_bytes(reader, pdu.lanId.data(), 7)) return false;

    // TODO: Parse TLVs from reader.remaining_data()
    return true;
}

bool parse_point_to_point_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PointToPointHelloPdu& pdu) {
    pdu.commonHeader = common_header;
    // TODO: Implement actual parsing
    return true;
}

bool parse_link_state_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LinkStatePdu& pdu) {
    pdu.commonHeader = common_header;
    BufferReader reader(pdu_data.data() + sizeof(CommonPduHeader), pdu_data.size() - sizeof(CommonPduHeader));

    if (!reader.can_read(2 + 2 + 7 + 4 + 2 + 1)) return false; // pduLength, lifetime, lspid, seq, checksum, PATTOLIS

    if (!parse_u16(reader, pdu.pduLength)) return false; // This is the LSP's own length field
    if (!parse_u16(reader, pdu.remainingLifetime)) return false;
    if (!parse_lsp_id(reader, pdu.lspId)) return false;
    if (!parse_u32(reader, pdu.sequenceNumber)) return false;
    if (!parse_u16(reader, pdu.checksum)) return false;
    if (!parse_u8(reader, pdu.pAttOlIsTypeBits)) return false;

    // TODO: Parse TLVs
    return true;
}

bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, CompleteSequenceNumbersPdu& pdu) {
    pdu.commonHeader = common_header;
    // TODO: Implement actual parsing
    return true;
}

bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PartialSequenceNumbersPdu& pdu) {
    pdu.commonHeader = common_header;
    // TODO: Implement actual parsing
    return true;
}

} // namespace isis
} // namespace netflow
