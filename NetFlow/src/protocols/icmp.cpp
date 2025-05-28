#include "netflow/protocols/icmp.h"
#include <vector>
#include <cstring>     // For memcpy
#include <numeric>     // For std::accumulate (though a manual loop is often clearer for checksum)
#include <arpa/inet.h> // For htons, ntohs, htonl, ntohl

namespace netflow {
namespace protocols {
namespace icmp {

// Utility function to calculate ICMP checksum
// Standard internet checksum algorithm
uint16_t calculate_icmp_checksum(const uint8_t* data, size_t length) {
    if (data == nullptr) return 0;

    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    size_t len_words = length / 2;

    for (size_t i = 0; i < len_words; ++i) {
        sum += ntohs(ptr[i]); // Use ntohs for consistent byte order before summing
    }

    if (length % 2 != 0) {
        // Add the last byte if length is odd, zero-padded to 16 bits
        sum += static_cast<uint32_t>(data[length - 1]) << 8;
    }

    // Add carries back to the sum
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement
    return htons(static_cast<uint16_t>(~sum));
}


std::vector<uint8_t> create_icmp_echo(
    uint8_t type,
    uint16_t identifier,
    uint16_t sequence_number,
    const std::vector<uint8_t>& payload) {

    size_t total_size = sizeof(IcmpHeader) + payload.size();
    std::vector<uint8_t> packet_data(total_size);

    IcmpHeader* header = reinterpret_cast<IcmpHeader*>(packet_data.data());
    header->type = type;
    header->code = 0;
    header->checksum = 0; // Placeholder for checksum calculation

    // Correctly place identifier and sequence number using network byte order
    uint16_t* p_id_seq = reinterpret_cast<uint16_t*>(&header->rest_of_header);
    *p_id_seq++ = htons(identifier); // First 2 bytes of rest_of_header
    *p_id_seq = htons(sequence_number); // Next 2 bytes of rest_of_header

    if (!payload.empty()) {
        std::memcpy(packet_data.data() + sizeof(IcmpHeader), payload.data(), payload.size());
    }

    header->checksum = calculate_icmp_checksum(packet_data.data(), total_size);
    return packet_data;
}

std::vector<uint8_t> create_icmp_dest_unreachable(
    uint8_t code,
    const uint8_t* original_ip_header_data, // Assumed 20 bytes
    const uint8_t* original_ip_payload_data // Assumed 8 bytes
) {
    const size_t original_ip_header_length = 20; // As specified
    const size_t original_payload_length = 8;    // As specified
    size_t total_size = sizeof(IcmpHeader) + original_ip_header_length + original_payload_length;
    std::vector<uint8_t> packet_data(total_size);

    IcmpHeader* header = reinterpret_cast<IcmpHeader*>(packet_data.data());
    header->type = ICMP_TYPE_DEST_UNREACH;
    header->code = code;
    header->checksum = 0;
    header->rest_of_header = 0; // Unused for Dest Unreachable

    uint8_t* payload_ptr = packet_data.data() + sizeof(IcmpHeader);
    if (original_ip_header_data) {
        std::memcpy(payload_ptr, original_ip_header_data, original_ip_header_length);
    }
    payload_ptr += original_ip_header_length;
    if (original_ip_payload_data) {
        std::memcpy(payload_ptr, original_ip_payload_data, original_payload_length);
    }

    header->checksum = calculate_icmp_checksum(packet_data.data(), total_size);
    return packet_data;
}

IcmpProcessResult process_icmp_packet(
    const uint8_t* icmp_packet_data,
    size_t icmp_packet_len,
    // uint32_t source_ip, // Not used in this implementation
    // uint32_t dest_ip,   // Not used in this implementation
    std::vector<uint8_t>& reply_icmp_packet_out // Corrected parameter name and meaning
) {
    if (!icmp_packet_data || icmp_packet_len < sizeof(IcmpHeader)) {
        return IcmpProcessResult::NONE;
    }

    // Create a mutable copy for checksum verification
    std::vector<uint8_t> temp_packet_data(icmp_packet_data, icmp_packet_data + icmp_packet_len);
    IcmpHeader* icmp_header_mutable = reinterpret_cast<IcmpHeader*>(temp_packet_data.data());
    
    uint16_t original_checksum = icmp_header_mutable->checksum;
    icmp_header_mutable->checksum = 0;
    uint16_t calculated_checksum = calculate_icmp_checksum(temp_packet_data.data(), icmp_packet_len);

    if (original_checksum != calculated_checksum) {
        return IcmpProcessResult::INVALID_CHECKSUM;
    }
    // Restore checksum if needed for further processing, though for this function, we use the original const data
    // icmp_header_mutable->checksum = original_checksum; // Not strictly needed here as we re-cast to const below

    const IcmpHeader* icmp_header = reinterpret_cast<const IcmpHeader*>(icmp_packet_data); // Use original const data

    switch (icmp_header->type) {
        case ICMP_TYPE_ECHO_REQUEST: {
            if (icmp_packet_len < sizeof(IcmpHeader)) return IcmpProcessResult::NONE; // Should have been caught, but good check

            const uint16_t* p_id_seq = reinterpret_cast<const uint16_t*>(&icmp_header->rest_of_header);
            uint16_t identifier = ntohs(*p_id_seq++);
            uint16_t sequence_number = ntohs(*p_id_seq);

            std::vector<uint8_t> payload_data;
            if (icmp_packet_len > sizeof(IcmpHeader)) {
                payload_data.assign(icmp_packet_data + sizeof(IcmpHeader),
                                    icmp_packet_data + icmp_packet_len);
            }

            reply_icmp_packet_out = create_icmp_echo(ICMP_TYPE_ECHO_REPLY,
                                                     identifier,
                                                     sequence_number,
                                                     payload_data);
            return IcmpProcessResult::ECHO_REQUEST_RECEIVED_REPLY_GENERATED;
        }
        case ICMP_TYPE_ECHO_REPLY: {
            // Optional: Log or notify about received echo reply.
            // For now, just acknowledge receipt.
            return IcmpProcessResult::ECHO_REPLY_RECEIVED;
        }
        case ICMP_TYPE_DEST_UNREACH: {
            // Optional: Log or handle the destination unreachable message.
            // For now, just acknowledge receipt.
            return IcmpProcessResult::DEST_UNREACHABLE_RECEIVED;
        }
        default:
            return IcmpProcessResult::NONE;
    }
}

}  // namespace icmp
}  // namespace protocols
}  // namespace netflow
