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

        int num_ip_bytes = (entry.subnetMask + 7) / 8;
        if (num_ip_bytes < 0 || num_ip_bytes > 4) return false; // Invalid prefix length

        if (!reader.can_read(static_cast<size_t>(num_ip_bytes))) return false;
        
        uint8_t ip_buf[4] = {0};
        if (!parse_bytes(reader, ip_buf, static_cast<size_t>(num_ip_bytes))) return false;
        
        uint32_t ip_val = 0;
        // Construct the IP address from potentially partial bytes (big-endian)
        for(int i=0; i < num_ip_bytes; ++i) {
            ip_val |= (static_cast<uint32_t>(ip_buf[i]) << ( (3-i) * 8) );
        }
        // The above reconstruction is incorrect for prefixes not aligned to byte boundaries.
        // A simpler way for now, assuming it's always aligned or padded to fill up to 4 bytes if less than 4 bytes are transmitted.
        // For the purpose of this exercise, we'll read the bytes and store them.
        // A correct parsing requires careful bitwise operations if prefix isn't byte aligned.
        // Let's re-evaluate this part. The standard says "The IP address prefix is packed into the minimum number of octets".
        
        // Corrected approach for reading prefix:
        uint32_t raw_ip_prefix_be = 0; // Read into a big-endian integer
        std::memcpy(reinterpret_cast<uint8_t*>(&raw_ip_prefix_be) + (4 - num_ip_bytes), reader.current_ptr() - num_ip_bytes, num_ip_bytes); // This is still not quite right.
                                                                                                                                    // The bytes are already in network order.
        // Let's try simpler: copy bytes and then ntohl if needed.
        // We have already advanced the reader by num_ip_bytes.

        // The simplest form: assume the bytes represent the prefix in network order.
        // We need to reconstruct the full IP from the prefix bytes.
        // Example: 10.0.0.0/8 -> 0A transmitted. entry.ipAddress should be 0x0A000000
        // Example: 192.168.1.0/24 -> C0 A8 01 transmitted. entry.ipAddress should be 0xC0A80100
        // Example: 172.16.0.0/12 -> AC 10 transmitted (AC 1), then need to handle the half byte.
        // For now, let's assume the prefix read is the full IP address, and mask is separate.
        // This is a simplification. A robust parser would handle bitmasks.
        // The problem states "prefix itself (only the significant bytes based on prefix length)"
        
        uint32_t ip_address_host_order = 0;
        const uint8_t* ip_start_ptr = reader.current_ptr() - num_ip_bytes; // pointer to start of IP bytes
        for (int i = 0; i < num_ip_bytes; ++i) {
            ip_address_host_order |= (static_cast<uint32_t>(ip_start_ptr[i]) << ((3 - i) * 8));
        }
        // This forms an IP using the bytes as the most significant bytes.
        // e.g., if 1 byte "0A" is read for /8, ip_address_host_order = 0x0A000000
        // e.g., if 2 bytes "C0A8" are read for /16, ip_address_host_order = 0xC0A80000
        // This is a common way to represent prefixes.
        entry.ipAddress = ip_address_host_order;

        out_value.reachabilityEntries.push_back(entry);
        // TODO: Add sub-TLV parsing if any
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
    size_t pdu_specific_start_offset = buffer.size();

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
    if (total_pdu_length > 255) {
        // This situation is problematic if lengthIndicator is the sole length field.
        // For robustness, one might set it to 0 or 255, or a specific value
        // indicating that a larger (e.g., 2-byte) length field elsewhere should be used.
        // Given the current structs, we must truncate or signal error.
        // For now, let's cap it at 255.
        buffer[1] = 255;
    } else {
        buffer[1] = static_cast<uint8_t>(total_pdu_length);
    }
    return buffer;
}

std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    
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
    if (total_pdu_length > 255) buffer[1] = 255;
    else buffer[1] = static_cast<uint8_t>(total_pdu_length);
    
    return buffer;
}

std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu) {
    // Temp buffer for common header to allow pduLengthLsp update later
    std::vector<uint8_t> common_header_bytes = serialize_common_pdu_header(pdu.commonHeader);
    std::vector<uint8_t> buffer;
    buffer.reserve(1500); // Pre-allocate
    append_bytes(buffer, common_header_bytes.data(), common_header_bytes.size());

    // pdu.pduLengthLsp is authoritative for LSP. It's the length from this field onwards.
    // So, we serialize the rest of the LSP, then calculate its length, then prepend it.
    // Or, serialize, then update.
    
    size_t lsp_header_start_offset = buffer.size(); // Start of pduLengthLsp field
    serialize_u16(buffer, 0); // Placeholder for pdu.pduLengthLsp
    serialize_u16(buffer, pdu.remainingLifetime);
    serialize_lsp_id(buffer, pdu.lspId);
    serialize_u32(buffer, pdu.sequenceNumber);
    serialize_u16(buffer, 0); // Checksum placeholder
    serialize_u8(buffer, pdu.pAttOlIsTypeBits);

    for (const auto& tlv : pdu.tlvs) {
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    // Calculate and update pduLengthLsp (total length of the LSP PDU)
    uint16_t total_lsp_length = static_cast<uint16_t>(buffer.size());
    uint16_t pdu_length_lsp_val_be = htons(total_lsp_length);
    std::memcpy(buffer.data() + lsp_header_start_offset, &pdu_length_lsp_val_be, sizeof(pdu_length_lsp_val_be));
    
    // Update CommonPduHeader.lengthIndicator
    // As per standard, this 1-byte field is also total PDU length.
    // If total_lsp_length > 255, this field is problematic.
    // Set to min(255, total_lsp_length) or a convention like 0xFF.
    if (total_lsp_length > 255) {
        buffer[1] = 255; // Or 0, or 0xFF as per some conventions if a larger length field exists
    } else {
        buffer[1] = static_cast<uint8_t>(total_lsp_length);
    }
    
    // The field pdu.pduLengthLsp in the struct should ideally match total_lsp_length.
    // The serialization uses the actual size.

    return buffer;
}

std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    // Note: Standard CSNP has a 2-byte PDU length field.
    // Our struct relies on commonHeader.lengthIndicator.
    serialize_system_id(buffer, pdu.sourceId);
    serialize_lsp_id(buffer, pdu.startLspId);
    serialize_lsp_id(buffer, pdu.endLspId);

    for (const auto& tlv : pdu.tlvs) { // Assuming TLVs carry LSP Entries
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());
    if (total_pdu_length > 255) buffer[1] = 255;
    else buffer[1] = static_cast<uint8_t>(total_pdu_length);
    
    return buffer;
}

std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu) {
    std::vector<uint8_t> buffer = serialize_common_pdu_header(pdu.commonHeader);
    // Note: Standard PSNP has a 2-byte PDU length field.
    // Our struct relies on commonHeader.lengthIndicator.
    serialize_system_id(buffer, pdu.sourceId);

    for (const auto& tlv : pdu.tlvs) { // Assuming TLVs carry LSP Entries
        std::vector<uint8_t> tlv_bytes = serialize_tlv(tlv);
        append_bytes(buffer, tlv_bytes.data(), tlv_bytes.size());
    }

    uint16_t total_pdu_length = static_cast<uint16_t>(buffer.size());
    if (total_pdu_length > 255) buffer[1] = 255;
    else buffer[1] = static_cast<uint8_t>(total_pdu_length);

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
    
    // The commonHeader.lengthIndicator (1 byte) is the total PDU length for IIH, CSNP, PSNP
    // as per the provided C++ structs, as they lack a dedicated 2-byte PDU length field.
    // For LSP, commonHeader.lengthIndicator is also total length (capped at 255),
    // but pduLengthLsp (2 bytes) is the more precise total length.

    // Validate PDU length from header against actual buffer size passed to parse function.
    // The effective_length determines the boundary for parsing this PDU.
    size_t effective_length = out_header.lengthIndicator; 
    // For LSP, pduLengthLsp will be parsed and used later, overriding reader.size.

    if (effective_length == 0) return false; // PDU length cannot be 0.
                                             // (Some specs say length 0xFF means use 2-byte field,
                                             // but our structs don't support that uniformly yet)
    if (effective_length > buffer.size()) return false; 
    
    // Adjust reader's view to only the PDU's claimed size (initially based on lengthIndicator)
    // This will be overridden for LSPs when pduLengthLsp is parsed.
    reader.size = effective_length;

    out_pdu.commonHeader = out_header;

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
    
    size_t effective_length = out_header.lengthIndicator;
    if (effective_length == 0 || effective_length > buffer.size()) return false;
    reader.size = effective_length;

    out_pdu.commonHeader = out_header;
    if (!parse_u8(reader, out_pdu.circuitType)) return false;
    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    if (!parse_u16(reader, out_pdu.holdingTime)) return false;
    // Standard PTP IIH has a 2-byte PDU length field here.
    // Our struct relies on commonHeader.lengthIndicator.
    if (!parse_u8(reader, out_pdu.localCircuitId)) return false;

    out_pdu.tlvs.clear();
    while(reader.offset < reader.size) {
        TLV tlv;
        if (reader.size - reader.offset < 2) break;
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
    // This field specifies the total length of the PDU, from the IRPD octet.
    uint16_t pduLengthLspField;
    if (!parse_u16(reader, pduLengthLspField)) return false;
    out_pdu.pduLengthLsp = pduLengthLspField;

    // Validate this length. It should not be smaller than the already parsed part.
    // (CommonHeader + pduLengthLsp field itself).
    size_t min_lsp_len = reader.offset; // Current offset is after reading pduLengthLsp field
    if (out_pdu.pduLengthLsp < min_lsp_len) return false; // PDU length too short

    // The buffer passed to this function must be at least out_pdu.pduLengthLsp bytes.
    if (out_pdu.pduLengthLsp > buffer.size()) return false; // Declared LSP length exceeds available buffer.
    
    // Adjust reader.size to the authoritative LSP length.
    // The reader.offset is currently at the start of the common header (from BufferReader construction).
    // No, reader.offset is currently *after* pduLengthLsp field.
    // The boundary for parsing this LSP is defined by out_pdu.pduLengthLsp,
    // which is an absolute length from the start of the PDU.
    reader.size = out_pdu.pduLengthLsp;


    if (!parse_u16(reader, out_pdu.remainingLifetime)) return false;
    if (!parse_lsp_id(reader, out_pdu.lspId)) return false;
    if (!parse_u32(reader, out_pdu.sequenceNumber)) return false;
    if (!parse_u16(reader, out_pdu.checksum)) return false; 
    if (!parse_u8(reader, out_pdu.pAttOlIsTypeBits)) return false;

    out_pdu.tlvs.clear();
    // Loop to parse TLVs. reader.offset is absolute from start of PDU.
    // reader.size is pduLengthLsp, also absolute from start of PDU.
    while(reader.offset < reader.size) { 
        if (reader.size - reader.offset < 2) { // Not enough for TLV type and length
             // Could be padding. If exactly at end, it's fine.
            break; 
        }
        TLV tlv;
        if (!parse_tlv(reader, tlv)) return false; 
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size; // Ensure all bytes of the LSP are consumed
}

bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, CompleteSequenceNumbersPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;

    // Standard CSNP has a 2-byte PDU length field after common header, similar to LSP.
    // Our struct relies on commonHeader.lengthIndicator (1 byte). This limits CSNP size.
    size_t effective_length = out_header.lengthIndicator;
    if (effective_length == 0 || effective_length > buffer.size()) return false;
    reader.size = effective_length; // Boundary for parsing this CSNP

    out_pdu.commonHeader = out_header;
    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    if (!parse_lsp_id(reader, out_pdu.startLspId)) return false;
    if (!parse_lsp_id(reader, out_pdu.endLspId)) return false;

    out_pdu.tlvs.clear(); 
    while(reader.offset < reader.size) {
        TLV tlv;
        if (reader.size - reader.offset < 2) break;
        if (!parse_tlv(reader, tlv)) return false;
        out_pdu.tlvs.push_back(tlv);
    }
    return reader.offset == reader.size;
}

bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& buffer, CommonPduHeader& out_header, PartialSequenceNumbersPdu& out_pdu) {
    BufferReader reader(buffer);
    if (!parse_common_pdu_header(reader, out_header)) return false;
    
    // Standard PSNP has a 2-byte PDU length field. Our struct uses 1-byte commonHeader.lengthIndicator.
    size_t effective_length = out_header.lengthIndicator;
    if (effective_length == 0 || effective_length > buffer.size()) return false;
    reader.size = effective_length; // Boundary for parsing this PSNP

    out_pdu.commonHeader = out_header;
    if (!parse_system_id(reader, out_pdu.sourceId)) return false;
    
    out_pdu.tlvs.clear(); 
    while(reader.offset < reader.size) {
        TLV tlv;
        if (reader.size - reader.offset < 2) break;
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
