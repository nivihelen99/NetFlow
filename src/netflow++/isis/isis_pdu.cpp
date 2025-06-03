#include "netflow++/isis/isis_pdu.hpp"
#include <vector>
#include <cstring> // For memcpy
#include <algorithm> // For std::copy
#include <arpa/inet.h> // For htons, htonl, ntohs, ntohl

namespace netflow {
namespace isis {

// --- Helper Functions for Serialization (Network Byte Order) ---

static void append_bytes(std::vector<uint8_t>& buffer, const uint8_t* data, size_t size) {
    buffer.insert(buffer.end(), data, data + size);
}

static void serialize_u8(std::vector<uint8_t>& buffer, uint8_t value) {
    buffer.push_back(value);
}

static void serialize_u16(std::vector<uint8_t>& buffer, uint16_t value) {
    value = htons(value);
    append_bytes(buffer, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
}

static void serialize_u32(std::vector<uint8_t>& buffer, uint32_t value) {
    value = htonl(value);
    append_bytes(buffer, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
}

static void serialize_system_id(std::vector<uint8_t>& buffer, const SystemID& id) {
    append_bytes(buffer, id.data(), id.size());
}

static void serialize_lsp_id(std::vector<uint8_t>& buffer, const LspId& id) {
    serialize_system_id(buffer, id.systemId);
    serialize_u8(buffer, id.pseudonodeIdOrLspNumber);
}

// --- Helper Functions for Deserialization (Network Byte Order) ---

struct BufferReader {
    const uint8_t* data;
    size_t size;
    size_t offset;

    BufferReader(const std::vector<uint8_t>& buffer) : data(buffer.data()), size(buffer.size()), offset(0) {}
    BufferReader(const uint8_t* buf_data, size_t buf_size) : data(buf_data), size(buf_size), offset(0) {}


    bool can_read(size_t num_bytes) const {
        return offset + num_bytes <= size;
    }

    const uint8_t* current_ptr() const {
        return data + offset;
    }

    void advance(size_t num_bytes) {
        offset += num_bytes;
    }
};

static bool parse_u8(BufferReader& reader, uint8_t& value) {
    if (!reader.can_read(sizeof(value))) return false;
    value = reader.current_ptr()[0];
    reader.advance(sizeof(value));
    return true;
}

static bool parse_u16(BufferReader& reader, uint16_t& value) {
    if (!reader.can_read(sizeof(value))) return false;
    std::memcpy(&value, reader.current_ptr(), sizeof(value));
    reader.advance(sizeof(value));
    value = ntohs(value);
    return true;
}

static bool parse_u32(BufferReader& reader, uint32_t& value) {
    if (!reader.can_read(sizeof(value))) return false;
    std::memcpy(&value, reader.current_ptr(), sizeof(value));
    reader.advance(sizeof(value));
    value = ntohl(value);
    return true;
}

static bool parse_bytes(BufferReader& reader, uint8_t* out_data, size_t num_bytes) {
    if (!reader.can_read(num_bytes)) return false;
    std::memcpy(out_data, reader.current_ptr(), num_bytes);
    reader.advance(num_bytes);
    return true;
}

static bool parse_system_id(BufferReader& reader, SystemID& id) {
    return parse_bytes(reader, id.data(), id.size());
}

static bool parse_lsp_id(BufferReader& reader, LspId& id) {
    if (!parse_system_id(reader, id.systemId)) return false;
    return parse_u8(reader, id.pseudonodeIdOrLspNumber);
}

// --- Fletcher Checksum Calculation (ISO 9592, Annex C) ---
// data: The byte array over which checksum is calculated.
// length: Length of the data.
// checksum_field_offset_in_data: Byte offset of the 2-byte checksum field within 'data'.
//                                These two bytes in 'data' are treated as zero during calculation.
static uint16_t calculate_fletcher_checksum(const uint8_t* data, size_t length, size_t checksum_field_offset_in_data) {
    uint32_t c0 = 0, c1 = 0; // Use uint32_t to prevent overflow during intermediate sums before modulo

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte_val = data[i];
        // If current byte is part of the checksum field, treat it as 0
        if (i == checksum_field_offset_in_data || i == checksum_field_offset_in_data + 1) {
            byte_val = 0;
        }
        c0 = (c0 + byte_val) % 255;
        c1 = (c1 + c0) % 255;
    }

    // The final checksum is ((C1 * 256) + C0), but some interpretations exist.
    // A common one for IS-IS: ( (octet_x * C1) - C0 ) mod 255 for the first checksum octet
    // and ( (octet_x_plus_1 * C1) + C0 ) mod 255 for the second.
    // RFC1142 / ISO 9592 specifies:
    // Octet X (Checksum byte 1): (length - checksum_field_offset_in_data) * C0 - C1 (mod 255)
    // Octet Y (Checksum byte 2): C1 - (length - checksum_field_offset_in_data - 1) * C0 (mod 255)
    // However, the implementation in common libraries (like Quagga/FRR) is simpler:
    // Checksum byte 1 = C0
    // Checksum byte 2 = C1
    // Let's re-verify the exact formula from ISO 9592.
    // The "OSI IS-IS Intra-domain Routing Protocol" (RFC 1142) refers to ISO 9592.
    // ISO/IEC 10589:2002(E), Annex C, section C.2.3 "Derivation of the checksum"
    //   X = C1 - (N+1) * C0
    //   Y = C0 - N * X
    // where N is the number of octets over which the checksum is calculated (i.e. 'length').
    // This seems overly complex compared to implementations.
    //
    // A widely cited and implemented version (e.g. Perl's Net::ISIS::LSP->checksum, Python ISIS libraries):
    //   Iterate:
    //     c0 = (c0 + byte) % 255;
    //     c1 = (c1 + c0) % 255;
    //   Checksum first byte: ((length - checksum_field_offset_in_data) * c0 - c1) % 255
    //   Checksum second byte: (c1 - (length - checksum_field_offset_in_data + 1) * c0) % 255
    //   This is also complex.
    //
    // Let's use the formula from RFC1142's Errata (ID 1053), which clarifies it to match common implementations:
    // It states the C code in the appendix of RFC1142 is correct.
    // The C code in RFC1142 Appendix B:
    // for (i=0; i < length; i++) {
    //    if (i == checksum_octet_1_offset || i == checksum_octet_2_offset) value = 0; else value = *p++;
    //    c0 = (c0 + value) % 255;
    //    c1 = (c1 + c0) % 255;
    // }
    // Checksum Octet 1 = -c1 % 255 (this is equivalent to (255 - (c1 % 255)) % 255 if c1 is not 0)
    // Checksum Octet 2 = c0 % 255
    // No, this is for IP header.
    //
    // Let's use the algorithm from ISO/IEC 10589:2002(E) Annex C directly, simplified:
    // C.2.2 Algorithm
    //   Initialize C0 and C1 to zero.
    //   For each octet in the PDU (from first octet of Remaining Lifetime to last octet of PDU):
    //     If the octet is one of the two checksum octets, treat it as zero.
    //     C0 := (C0 + value_of_octet) MOD 255
    //     C1 := (C1 + C0) MOD 255
    //   End Loop.
    //   The two octets of the checksum field (CH1, CH2) are then:
    //   CH1 = ((N - P) * C0 - C1) MOD 255
    //   CH2 = (C1 - (N - P + 1) * C0) MOD 255
    //   Where:
    //     N is the number of octets in the part of the PDU being checksummed (i.e., 'length').
    //     P is the offset (0-indexed) of the first octet of the checksum field from the
    //       start of the part of the PDU being checksummed (i.e., 'checksum_field_offset_in_data').

    // After the loop, C0 and C1 hold the final sums.
    int n_val = static_cast<int>(length);
    int p_val = static_cast<int>(checksum_field_offset_in_data);

    // Ensure intermediate calculations do not underflow with modulo of negative numbers.
    // (a % n + n) % n gives a positive result for negative a.
    int ch1_val = ( (n_val - p_val) * c0 - c1 ) % 255;
    if (ch1_val < 0) ch1_val += 255;

    int ch2_val = ( c1 - (n_val - p_val + 1) * c0 ) % 255;
    if (ch2_val < 0) ch2_val += 255;

    return (static_cast<uint16_t>(ch1_val) << 8) | static_cast<uint16_t>(ch2_val);
}


// --- TLV Serialization ---

static std::vector<uint8_t> serialize_tlv_header(uint8_t type, uint8_t length) {
    std::vector<uint8_t> header_bytes;
    serialize_u8(header_bytes, type);
    serialize_u8(header_bytes, length);
    return header_bytes;
}

std::vector<uint8_t> serialize_tlv(const TLV& tlv) {
    std::vector<uint8_t> buffer;
    serialize_u8(buffer, tlv.type);
    serialize_u8(buffer, tlv.length);
    append_bytes(buffer, tlv.value.data(), tlv.value.size());
    return buffer;
}

// --- TLV Value Serialization ---

std::vector<uint8_t> serialize_area_addresses_tlv_value(const AreaAddressesTlvValue& value) {
    std::vector<uint8_t> buffer;
    for (const auto& area_addr : value.areaAddresses) {
        serialize_u8(buffer, static_cast<uint8_t>(area_addr.size())); // Length of one area address
        append_bytes(buffer, area_addr.data(), area_addr.size());
    }
    return buffer;
}

std::vector<uint8_t> serialize_extended_ip_reachability_tlv_value(const ExtendedIpReachabilityTlvValue& value) {
    std::vector<uint8_t> buffer;
    for (const auto& entry : value.reachabilityEntries) {
        serialize_u32(buffer, entry.metric);
        // Assuming entry.subnetMask is prefix length for TLV 135
        serialize_u8(buffer, static_cast<uint8_t>(entry.subnetMask)); // Prefix length

        uint32_t ip_addr_be = htonl(entry.ipAddress);
        int num_ip_bytes = (entry.subnetMask + 7) / 8; // Calculate bytes needed for prefix
        if (num_ip_bytes < 0) num_ip_bytes = 0;
        if (num_ip_bytes > 4) num_ip_bytes = 4; // Max 4 bytes for IPv4

        append_bytes(buffer, reinterpret_cast<const uint8_t*>(&ip_addr_be), static_cast<size_t>(num_ip_bytes));
        // TODO: Add sub-TLV serialization if any
    }
    return buffer;
}

// --- TLV Value Deserialization ---

bool parse_area_addresses_tlv_value(const std::vector<uint8_t>& value_bytes, AreaAddressesTlvValue& out_value) {
    BufferReader reader(value_bytes);
    out_value.areaAddresses.clear();
    while (reader.offset < reader.size) {
        uint8_t area_len;
        if (!parse_u8(reader, area_len)) return false;
        if (!reader.can_read(area_len)) return false;
        AreaAddress current_area(area_len);
        if (!parse_bytes(reader, current_area.data(), area_len)) return false;
        out_value.areaAddresses.push_back(current_area);
    }
    return true;
}

bool parse_extended_ip_reachability_tlv_value(const std::vector<uint8_t>& value_bytes, ExtendedIpReachabilityTlvValue& out_value) {
    BufferReader reader(value_bytes);
    out_value.reachabilityEntries.clear();
    // Assuming no sub-TLVs for now for simplicity
    while(reader.offset < reader.size) {
        IpReachabilityInfo entry;
        if (!parse_u32(reader, entry.metric)) return false;
        
        uint8_t prefix_len_u8;
        if (!parse_u8(reader, prefix_len_u8)) return false;
        entry.subnetMask = prefix_len_u8; // Storing prefix length in subnetMask field

        int num_ip_bytes = (prefix_len_u8 + 7) / 8;
        if (num_ip_bytes < 0 || num_ip_bytes > 4) return false; // Invalid prefix length calculation

        if (!reader.can_read(static_cast<size_t>(num_ip_bytes))) return false; // Not enough bytes for prefix
        
        uint32_t ip_address_host_order = 0;
        const uint8_t* prefix_bytes_ptr = reader.current_ptr();
        for (int i = 0; i < num_ip_bytes; ++i) {
            // Shift byte into the correct position in the uint32_t.
            // For a 4-byte IP: byte 0 is MSB (shifted 24 bits), byte 1 (shifted 16), etc.
            ip_address_host_order |= (static_cast<uint32_t>(prefix_bytes_ptr[i]) << ((3 - i) * 8));
        }
        reader.advance(static_cast<size_t>(num_ip_bytes));
        entry.ipAddress = ip_address_host_order; // Store the reconstructed IP (host order)

        // entry.subnetMask already stores prefix_len_u8.

        out_value.reachabilityEntries.push_back(entry);
        // TODO: Add sub-TLV parsing if any (not part of this subtask)
    }
    return true;
}


// --- PDU Serialization ---

std::vector<uint8_t> serialize_common_pdu_header(const CommonPduHeader& header) {
    std::vector<uint8_t> buffer;
    serialize_u8(buffer, header.intradomainRoutingProtocolDiscriminator);
    serialize_u8(buffer, header.lengthIndicator); // Will be updated by PDU-specific serializers
    serialize_u8(buffer, header.versionProtocolIdExtension);
    serialize_u8(buffer, header.idLength);
    serialize_u8(buffer, header.pduType);
    serialize_u8(buffer, header.version);
    serialize_u8(buffer, header.reserved);
    serialize_u8(buffer, header.maxAreaAddresses);
    return buffer;
}


std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    // Current offset where PDU specific data starts
    size_t common_header_size = buffer.size();
    // Serialize the 2-byte pduLength, placeholder for now
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLength

    serialize_u8(buffer, pdu.circuitType);
    serialize_system_id(buffer, pdu.sourceId);
    serialize_u16(buffer, pdu.holdingTime);
    serialize_u8(buffer, pdu.priority);
    append_bytes(buffer, pdu.lanId.data(), pdu.lanId.size());

    for (const auto& tlv : pdu.tlvs) {
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }
    
    // Update commonHeader.lengthIndicator (1 byte)
    // This field, as per ISO10589, is the total PDU length.
    // If total_pdu_length > 255, this field cannot represent it.
    // This is a limitation of the 1-byte field if it's the *only* length field.
    // However, PDUs like LSP have their own 2-byte length field.
    // For PDUs without their own 2-byte length field in their struct (IIH, CSNP, PSNP as defined here),
    // we are constrained by this 1-byte field.
    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());

    // Update the 2-byte pduLength field in the buffer
    uint16_t pdu_length_val_be = htons(total_pdu_length);
    std::memcpy(buffer.data() + common_header_size, &pdu_length_val_be, sizeof(pdu_length_val_be));

    // Update commonHeader.lengthIndicator (1 byte)
    if (total_pdu_length > 255) {
        buffer[1] = 0xFF; // Indicate that the 2-byte field should be used
    } else {
        buffer[1] = static_cast<uint8_t>(total_pdu_length);
    }
    return buffer;
}

std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    size_t common_header_size = buffer.size();
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLength
    
    serialize_u8(buffer, pdu.circuitType);
    serialize_system_id(buffer, pdu.sourceId);
    serialize_u16(buffer, pdu.holdingTime);
    // Note: Standard PTP IIH has a 2-byte PDU length field here.
    // Our struct relies on commonHeader.lengthIndicator.
    serialize_u8(buffer, pdu.localCircuitId);

    for (const auto& tlv : pdu.tlvs) {
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }
    
    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());
    uint16_t pdu_length_val_be = htons(total_pdu_length);
    std::memcpy(buffer.data() + common_header_size, &pdu_length_val_be, sizeof(pdu_length_val_be));

    if (total_pdu_length > 255) {
        buffer[1] = 0xFF;
    } else {
        buffer[1] = static_cast<uint8_t>(total_pdu_length);
    }
    
    return buffer;
}

std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu) {
    // Temp buffer for common header to allow pduLength update later
    std::vector<uint8_t> common_header_bytes = serialize_common_pdu_header(pdu.commonHeader);
    std::vector<uint8_t> buffer;
    buffer.reserve(1500); // Pre-allocate
    append_bytes(buffer, common_header_bytes.data(), common_header_bytes.size());

    // pdu.pduLength is authoritative for LSP.
    // The field in the struct is `pdu.pduLength`. The field name in LinkStatePdu was pduLengthLsp, now pduLength.
    // The value serialized is the total PDU length.

    size_t pdu_length_field_offset = buffer.size(); // Start of the 2-byte pduLength field
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLength (the total PDU length)
    
    size_t remaining_lifetime_offset = buffer.size();
    serialize_u16(buffer, pdu.remainingLifetime);
    serialize_lsp_id(buffer, pdu.lspId);
    serialize_u32(buffer, pdu.sequenceNumber);

    size_t checksum_field_absolute_offset_in_pdu = buffer.size();
    // Serialize the checksum from the struct (usually 0 for new LSPs, or existing for re-serialization)
    // This will be overwritten by calculation for new LSPs.
    serialize_u16(buffer, pdu.checksum);
    serialize_u8(buffer, pdu.pAttOlIsTypeBits);

    for (const auto& tlv : pdu.tlvs) {
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    // Calculate and update pduLength (total length of the LSP PDU)
    uint16_t total_lsp_length = static_cast<uint16_t>(buffer.size());
    // The pdu.pduLength field in the LinkStatePdu struct itself should be set by the caller
    // to this total_lsp_length if it needs to be accurate before serialization.
    // Here, we ensure the serialized field has the correct calculated total length.
    uint16_t pdu_length_val_be = htons(total_lsp_length);
    std::memcpy(buffer.data() + pdu_length_field_offset, &pdu_length_val_be, sizeof(pdu_length_val_be));
    
    // Update CommonPduHeader.lengthIndicator
    if (total_lsp_length > 255) {
        buffer[1] = 0xFF; // Indicate that the 2-byte field should be used
    } else {
        buffer[1] = static_cast<uint8_t>(total_lsp_length);
    }
    
    // The field pdu.pduLength in the struct (if it was an input) is not directly used here for calculation,
    // we calculate based on serialized content.

    // --- Fletcher Checksum Calculation and Insertion ---
    // The checksum is calculated over the LSP content starting from 'Remaining Lifetime'
    // up to the end of the PDU (i.e., end of TLVs).
    // The CommonPduHeader is 8 bytes. The pduLength field (total PDU length of LSP) is 2 bytes.
    // So, 'Remaining Lifetime' starts at offset 10 from the beginning of the 'buffer'.
    const size_t lsp_content_for_checksum_start_offset = remaining_lifetime_offset; // This is offset from pdu_length_field_offset + 2
                                                                               // No, this should be from start of buffer.
                                                                               // common_header_bytes.size() + sizeof(uint16_t) for pduLength

    // total_lsp_length is already calculated as buffer.size()
    // common_header_bytes.size() is the size of CommonPduHeader.
    // The pdu.pduLength field itself is part of the PDU, but not part of checksummable content typically.
    // ISO 10589: "The checksum shall be calculated over the entire PDU including the PDU header,
    // with the two octets of the Checksum field being set to zero."
    // BUT for LSPs, it's "from the first octet of the Remaining Lifetime field to the last octet of the PDU".
    // Let's re-verify the start offset for checksum calculation.
    // `common_header_bytes` contains the common header. `pdu_length_field_offset` is its size.
    // So `pdu_length_field_offset` is the start of the 2-byte PDU length field.
    // `remaining_lifetime_offset` is `pdu_length_field_offset + 2`. This is correct start for checksum.

    size_t checksum_calculation_start_offset_in_buffer = remaining_lifetime_offset;
    size_t checksum_calculation_length = total_lsp_length - checksum_calculation_start_offset_in_buffer;

    // The checksum field's offset relative to the start of the data block being checksummed.
    // Checksum field is at `checksum_field_absolute_offset_in_pdu`.
    // Data block for checksum starts at `checksum_calculation_start_offset_in_buffer`.
    size_t checksum_field_relative_offset_in_calc_data = checksum_field_absolute_offset_in_pdu - checksum_calculation_start_offset_in_buffer;

    // Temporarily zero out the checksum field in the buffer for calculation
    // The serialize_u16 for checksum already wrote pdu.checksum. We need to save and restore if not zero,
    // or just overwrite. For calculation, it must be treated as zero.
    // The calculate_fletcher_checksum function handles treating it as zero via offset.
    // So, we don't need to modify the buffer before calling it.

    uint16_t calculated_checksum_val = calculate_fletcher_checksum(
        buffer.data() + checksum_calculation_start_offset_in_buffer,
        checksum_calculation_length,
        checksum_field_relative_offset_in_calc_data
    );

    uint16_t checksum_be = htons(calculated_checksum_val);
    std::memcpy(buffer.data() + checksum_field_absolute_offset_in_pdu, &checksum_be, sizeof(checksum_be));

    return buffer;
}

std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    size_t common_header_size = buffer.size();
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLength

    serialize_system_id(buffer, pdu.sourceId);
    serialize_lsp_id(buffer, pdu.startLspId);
    serialize_lsp_id(buffer, pdu.endLspId);

    for (const auto& tlv : pdu.tlvs) { // Assuming TLVs carry LSP Entries
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());
    uint16_t pdu_length_val_be = htons(total_pdu_length);
    std::memcpy(buffer.data() + common_header_size, &pdu_length_val_be, sizeof(pdu_length_val_be));

    if (total_pdu_length > 255) {
        buffer[1] = 0xFF;
    } else {
        buffer[1] = static_cast<uint8_t>(total_pdu_length);
    }
    
    return buffer;
}

std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    size_t common_header_size = buffer.size();
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLength

    serialize_system_id(buffer, pdu.sourceId);

    for (const auto& tlv : pdu.tlvs) { // Assuming TLVs carry LSP Entries
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());
    uint16_t pdu_length_val_be = htons(total_pdu_length);
    std::memcpy(buffer.data() + common_header_size, &pdu_length_val_be, sizeof(pdu_length_val_be));

    if (total_pdu_length > 255) {
        buffer[1] = 0xFF;
    } else {
        buffer[1] = static_cast<uint8_t>(total_pdu_length);
    }
    return buffer;
}


// --- PDU Deserialization ---

bool parse_common_pdu_header(BufferReader& reader, CommonPduHeader& out_header) {
    if (!parse_u8(reader, out_header.intradomainRoutingProtocolDiscriminator)) return false;
    if (!parse_u8(reader, out_header.lengthIndicator)) return false; // This is the 1-byte total PDU length as per struct
    if (!parse_u8(reader, out_header.versionProtocolIdExtension)) return false;
    if (!parse_u8(reader, out_header.idLength)) return false;
    if (!parse_u8(reader, out_header.pduType)) return false;
    if (!parse_u8(reader, out_header.version)) return false;
    if (!parse_u8(reader, out_header.reserved)) return false;
    if (!parse_u8(reader, out_header.maxAreaAddresses)) return false;
    return true;
}

bool parse_tlv(BufferReader& reader, TLV& out_tlv) {
    if (!parse_u8(reader, out_tlv.type)) return false;
    if (!parse_u8(reader, out_tlv.length)) return false;
    if (!reader.can_read(out_tlv.length)) return false;
    out_tlv.value.resize(out_tlv.length);
    if (!parse_bytes(reader, out_tlv.value.data(), out_tlv.length)) return false;
    return true;
}

bool parse_lan_hello_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, LanHelloPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;
    out_pdu.commonHeader = out_header; // Copy common header

    // Parse the 2-byte pduLength field
    if (!parse_u16(reader, out_pdu.pduLength)) return false;

    // Validate PDU length. The 2-byte pduLength is authoritative.
    if (out_pdu.pduLength < reader.offset) return false; // PDU length too short to even contain the fields read so far
    if (out_pdu.pduLength > buffer.size()) return false; // Declared PDU length exceeds available buffer.
    
    // Cross-check with commonHeader.lengthIndicator
    if (out_header.lengthIndicator != 0xFF && out_header.lengthIndicator != static_cast<uint8_t>(std::min(out_pdu.pduLength, 255u))) {
        // Optional: Log a warning about mismatch if not 0xFF
        // For now, we trust pduLength.
    }
    if (out_header.lengthIndicator == 0xFF && out_pdu.pduLength <= 255) {
        // Optional: Log a warning, 0xFF implies larger PDU, but pduLength fits in 1 byte.
    }

    // Set the reader's boundary to the authoritative pduLength
    reader.size = out_pdu.pduLength;

    if (!parse_u8(reader, out_pdu.circuitType)) return false;
    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    if (!parse_u16(reader, out_pdu.holdingTime)) return false;
    // Standard LAN IIH has a 2-byte PDU length field here.
    // Our struct relies on commonHeader.lengthIndicator, so we don't parse a separate 2-byte length.

    if (!parse_u8(reader, out_pdu.priority)) return false;
    if (!parse_bytes(reader, out_pdu.lanId.data(), out_pdu.lanId.size())) return false;

    out_pdu.tlvs.clear();
    // Loop to parse TLVs until the end of the PDU (as defined by reader.size, which is from lengthIndicator)
    while(reader.offset < reader.size) { // Use reader.size as the boundary
        TLV current_tlv;
        // Check for padding (type 0 or 8 with length 0, or if remaining bytes too few for TLV header)
        if (reader.size - reader.offset < 2) break; // Not enough for TLV type and length

        if (!parse_u8(reader, current_tlv.type)) return false; 
        if (!parse_u8(reader, current_tlv.length)) return false;
        
        if (reader.offset + current_tlv.length > reader.size) return false; // TLV exceeds PDU
        
        current_tlv.value.resize(current_tlv.length);
        if (!parse_bytes(reader, current_tlv.value.data(), current_tlv.length)) return false;
        
        out_pdu.tlvs.push_back(current_tlv);
    }
    return reader.offset == reader.size; // Ensure we consumed the whole PDU as per its length
}

// Stubs for other PDU parsers
bool parse_point_to_point_hello_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, PointToPointHelloPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;
    out_pdu.commonHeader = out_header;

    if (!parse_u16(reader, out_pdu.pduLength)) return false;

    if (out_pdu.pduLength < reader.offset) return false;
    if (out_pdu.pduLength > buffer.size()) return false;

    if (out_header.lengthIndicator != 0xFF && out_header.lengthIndicator != static_cast<uint8_t>(std::min(out_pdu.pduLength, 255u))) {
        // Optional: Log warning
    }
     if (out_header.lengthIndicator == 0xFF && out_pdu.pduLength <= 255) {
        // Optional: Log warning
    }

    reader.size = out_pdu.pduLength;

    if (!parse_u8(reader, out_pdu.circuitType)) return false;
    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    if (!parse_u16(reader, out_pdu.holdingTime)) return false;
    // Standard PTP IIH has a 2-byte PDU length field here.
    // Our struct relies on commonHeader.lengthIndicator.
    if (!parse_u8(reader, out_pdu.localCircuitId)) return false;

    out_pdu.tlvs.clear();
    while(reader.offset < reader.size) {
        TLV tlv;
        // Check for padding: if remaining bytes are less than TLV header size, or if a padding TLV is found
        if (reader.size - reader.offset < 2) break;

        // Peek at type for padding TLV (type 8)
        uint8_t peek_type = reader.current_ptr()[0];
        if (peek_type == PADDING_TLV_TYPE) { // Assuming PADDING_TLV_TYPE = 8
            // Potentially skip padding TLVs or handle as per specific ISIS profile
            // For now, standard parsing. If it's a valid TLV, parse_tlv will handle it.
        }

        if (!parse_tlv(reader, tlv)) return false; 
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size;
}

bool parse_link_state_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, LinkStatePdu& out_pdu) {
    BufferReader reader(buffer);
    // Parse common header first to get initial lengthIndicator
    if (!parse_common_pdu_header(reader, out_header)) return false;
    out_pdu.commonHeader = out_header;

    // LSP has its own PDU Length field (2 bytes) which is authoritative.
    // This field was named pduLengthLsp, now pduLength in the struct.
    if (!parse_u16(reader, out_pdu.pduLength)) return false;

    // Validate this length. It should not be smaller than the already parsed part.
    // (CommonHeader + pduLength field itself).
    size_t min_lsp_len = reader.offset; // Current offset is after reading pduLength field
    if (out_pdu.pduLength < min_lsp_len) return false; // PDU length too short

    // The buffer passed to this function must be at least out_pdu.pduLength bytes.
    if (out_pdu.pduLength > buffer.size()) return false; // Declared LSP length exceeds available buffer.
    
    // Cross-check with commonHeader.lengthIndicator
    if (out_header.lengthIndicator != 0xFF && out_header.lengthIndicator != static_cast<uint8_t>(std::min(out_pdu.pduLength, 255u))) {
        // Optional: Log warning
    }
    if (out_header.lengthIndicator == 0xFF && out_pdu.pduLength <= 255) {
        // Optional: Log warning
    }

    // Adjust reader.size to the authoritative LSP length.
    reader.size = out_pdu.pduLength;


    if (!parse_u16(reader, out_pdu.remainingLifetime)) return false;
    if (!parse_lsp_id(reader, out_pdu.lspId)) return false;
    if (!parse_u32(reader, out_pdu.sequenceNumber)) return false;
    if (!parse_u16(reader, out_pdu.checksum)) return false; 
    if (!parse_u8(reader, out_pdu.pAttOlIsTypeBits)) return false;

    out_pdu.tlvs.clear();
    // Loop to parse TLVs. reader.offset is absolute from start of PDU.
    // reader.size is out_pdu.pduLength, also absolute from start of PDU.
    while(reader.offset < reader.size) { 
        if (reader.size - reader.offset < 2) { // Not enough for TLV type and length
             // Could be padding. If exactly at end, it's fine.
            break; 
        }
        TLV tlv;
        // Peek at type for padding TLV (type 8)
        uint8_t peek_type = reader.current_ptr()[0];
        if (peek_type == PADDING_TLV_TYPE) {
            // As per RFC 1195, padding TLV (type 8) can be used to make PDUs a desired length.
            // It should be parsed like a normal TLV.
        }
        if (!parse_tlv(reader, tlv)) return false; 
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size; // Ensure all bytes of the LSP are consumed
}

bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, CompleteSequenceNumbersPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;
    out_pdu.commonHeader = out_header;

    if (!parse_u16(reader, out_pdu.pduLength)) return false;

    if (out_pdu.pduLength < reader.offset) return false;
    if (out_pdu.pduLength > buffer.size()) return false;

    if (out_header.lengthIndicator != 0xFF && out_header.lengthIndicator != static_cast<uint8_t>(std::min(out_pdu.pduLength, 255u))) {
        // Optional: Log warning
    }
    if (out_header.lengthIndicator == 0xFF && out_pdu.pduLength <= 255) {
        // Optional: Log warning
    }

    reader.size = out_pdu.pduLength; // Boundary for parsing this CSNP

    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    if (!parse_lsp_id(reader, out_pdu.startLspId)) return false;
    if (!parse_lsp_id(reader, out_pdu.endLspId)) return false;

    out_pdu.tlvs.clear(); 
    while(reader.offset < reader.size) {
        TLV tlv;
        if (reader.size - reader.offset < 2) break;
        // Peek at type for padding TLV (type 8)
        uint8_t peek_type = reader.current_ptr()[0];
        if (peek_type == PADDING_TLV_TYPE) {
            // Handle padding if necessary, or just parse as regular TLV
        }
        if (!parse_tlv(reader, tlv)) return false;
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size;
}

bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, PartialSequenceNumbersPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;
    out_pdu.commonHeader = out_header;
    
    if (!parse_u16(reader, out_pdu.pduLength)) return false;

    if (out_pdu.pduLength < reader.offset) return false;
    if (out_pdu.pduLength > buffer.size()) return false;

    if (out_header.lengthIndicator != 0xFF && out_header.lengthIndicator != static_cast<uint8_t>(std::min(out_pdu.pduLength, 255u))) {
        // Optional: Log warning
    }
    if (out_header.lengthIndicator == 0xFF && out_pdu.pduLength <= 255) {
        // Optional: Log warning
    }

    reader.size = out_pdu.pduLength; // Boundary for parsing this PSNP

    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    
    out_pdu.tlvs.clear(); 
    while(reader.offset < reader.size) {
        TLV tlv;
        if (reader.size - reader.offset < 2) break;
        // Peek at type for padding TLV (type 8)
        uint8_t peek_type = reader.current_ptr()[0];
        if (peek_type == PADDING_TLV_TYPE) {
            // Handle padding if necessary
        }
        if (!parse_tlv(reader, tlv)) return false;
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size;
}


// --- New Multicast TLV Value Serialization/Deserialization ---

// MulticastCapabilityTlvValue (Type 230)
// Value is empty for now, so length is 0.
std::vector<uint8_t> serialize_multicast_capability_tlv_value(const MulticastCapabilityTlvValue& value) {
    // Empty value, TLV length will be 0.
    return {};
}

bool parse_multicast_capability_tlv_value(const std::vector<uint8_t>& value_bytes, MulticastCapabilityTlvValue& out_value) {
    if (!value_bytes.empty()) {
        // std::cerr << "Warning: MulticastCapabilityTlvValue expects empty value, but received " << value_bytes.size() << " bytes." << std::endl;
        // Depending on strictness, this could be an error. For now, allow but ignore.
    }
    // No fields to parse from value_bytes for an empty struct.
    return true;
}

// MulticastGroupMembershipTlvValue (Type 231)
std::vector<uint8_t> serialize_multicast_group_membership_tlv_value(const MulticastGroupMembershipTlvValue& value) {
    std::vector<uint8_t> buffer;
    for (const auto& group_info : value.groups) {
        // Serialize group_address (IpAddress is uint32_t in host order, convert to network)
        uint32_t group_addr_net = htonl(group_info.group_address.to_uint32()); // Assumes IpAddress has to_uint32()
        append_bytes(buffer, reinterpret_cast<const uint8_t*>(&group_addr_net), sizeof(group_addr_net));

        // Serialize source_address (IpAddress is uint32_t in host order, convert to network)
        uint32_t source_addr_net = htonl(group_info.source_address.to_uint32());
        append_bytes(buffer, reinterpret_cast<const uint8_t*>(&source_addr_net), sizeof(source_addr_net));
    }
    return buffer;
}

bool parse_multicast_group_membership_tlv_value(const std::vector<uint8_t>& value_bytes, MulticastGroupMembershipTlvValue& out_value) {
    out_value.groups.clear();
    BufferReader reader(value_bytes);
    
    // Each entry is group_address (4 bytes) + source_address (4 bytes) = 8 bytes
    if (reader.size % 8 != 0) {
        // std::cerr << "Error: MulticastGroupMembershipTlvValue has unexpected length " << reader.size << ", not a multiple of 8." << std::endl;
        return false; // Each entry should be 8 bytes
    }

    while (reader.can_read(8)) { // 4 bytes for group, 4 for source
        MulticastGroupAddressInfo group_info;
        uint32_t group_addr_net, source_addr_net;

        if (!parse_u32(reader, group_addr_net)) return false; // parse_u32 handles ntohl
        group_info.group_address = IpAddress(group_addr_net); // Assumes IpAddress constructor takes host order

        if (!parse_u32(reader, source_addr_net)) return false;
        group_info.source_address = IpAddress(source_addr_net);
        
        out_value.groups.push_back(group_info);
    }
    return reader.offset == reader.size; // Ensure all bytes consumed
}


// Placeholder for LspEntry serialization/deserialization if they are not within TLVs (standard is TLV type 9 or direct)
// For now, CSNP/PSNP are defined to use TLVs for LSP Entries.
// If LspEntry structs were part of a list directly in CSNP/PSNP:
/*
static void serialize_lsp_entry(std::vector<uint8_t>& buffer, const LspEntry& entry) {
    serialize_u16(buffer, entry.lifetime);
    serialize_lsp_id(buffer, entry.lspId);
    serialize_u32(buffer, entry.sequenceNumber);
    serialize_u16(buffer, entry.checksum);
}

static bool parse_lsp_entry(BufferReader& reader, LspEntry& out_entry) {
    if (!parse_u16(reader, out_entry.lifetime)) return false;
    if (!parse_lsp_id(reader, out_entry.lspId)) return false;
    if (!parse_u32(reader, out_entry.sequenceNumber)) return false;
    if (!parse_u16(reader, out_entry.checksum)) return false;
    return true;
}
*/

} // namespace isis
} // namespace netflow
