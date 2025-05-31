#ifndef NETFLOW_PACKET_HPP
#define NETFLOW_PACKET_HPP

#include "packet_buffer.hpp"
#include <cstdint>
#include <vector>
#include <optional> // Potentially useful for optional headers
#include <cstring>  // For memcpy, memmove
#include <algorithm> // For std::copy, std::fill, std::equal
#include <stdexcept> // For exceptions

// For network byte order functions like ntohs, htons.
// On Linux/POSIX, this is the typical header.
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>) // For Windows
#include <winsock2.h>
// It's common to need to link against ws2_32.lib on Windows
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
#else
// Provide basic fallback implementations if no standard header is found
// These might not be as optimized or complete as system versions.
#warning "System headers for network byte order functions (ntohs, htons) not found. Using basic fallbacks."
inline uint16_t htons(uint16_t val) {
    // Check endianness if possible, this is for big-endian systems if host is little-endian
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
    }
    return val;
}
inline uint16_t ntohs(uint16_t val) {
    // Same logic as htons for symmetry with this basic fallback
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
    }
    return val;
}
// Fallback for 32-bit. Note: Real system headers are more robust.
inline uint32_t htonl(uint32_t val) {
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF000000) >> 24) |
               ((val & 0x00FF0000) >>  8) |
               ((val & 0x0000FF00) <<  8) |
               ((val & 0x000000FF) << 24);
    }
    return val;
}
inline uint32_t ntohl(uint32_t val) {
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF000000) >> 24) |
               ((val & 0x00FF0000) >>  8) |
               ((val & 0x0000FF00) <<  8) |
               ((val & 0x000000FF) << 24);
    }
    return val;
}
#endif

namespace netflow {

// Placeholder for MAC Address
struct MacAddress {
    uint8_t bytes[6];

    MacAddress() {
        std::fill(bytes, bytes + 6, 0);
    }

    MacAddress(const uint8_t* mac_bytes) {
        std::copy(mac_bytes, mac_bytes + 6, bytes);
    }

    bool operator==(const MacAddress& other) const {
        return std::equal(bytes, bytes + 6, other.bytes);
    }
};

// Placeholder for Ethernet Header
struct EthernetHeader {
    MacAddress dst_mac;
    MacAddress src_mac;
    uint16_t ethertype; // e.g., 0x0800 for IPv4, 0x8100 for VLAN, 0x86DD for IPv6

    static constexpr size_t SIZE = sizeof(MacAddress) * 2 + sizeof(uint16_t);
};

// Placeholder for VLAN Header (802.1Q)
struct VlanHeader {
    uint16_t tci; // Tag Control Information (PCP: 3 bits, DEI: 1 bit, VID: 12 bits)
    uint16_t ethertype;

    static constexpr size_t SIZE = sizeof(uint16_t) * 2;

    uint16_t get_vlan_id() const {
        return ntohs(tci) & 0x0FFF;
    }
    uint8_t get_priority() const {
        return (ntohs(tci) >> 13) & 0x07;
    }
    void set_vlan_id(uint16_t id) {
        tci = htons((ntohs(tci) & 0xF000) | (id & 0x0FFF));
    }
    void set_priority(uint8_t prio) {
        tci = htons((ntohs(tci) & 0x1FFF) | ((prio & 0x07) << 13));
    }
};

// Definition for LLC Header
struct LLCHeader {
    uint8_t dsap;      // Destination Service Access Point
    uint8_t ssap;      // Source Service Access Point
    uint8_t control;   // Control field
    // For STP BPDUs, DSAP and SSAP are often 0x42, Control is 0x03 (UI frame)
    static constexpr size_t SIZE = 3;
};

// Placeholder for IPv4 Header
struct IPv4Header {
    uint8_t version_ihl; // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t dscp_ecn;    // Differentiated Services Code Point (6 bits) + Explicit Congestion Notification (2 bits)
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;
    uint8_t protocol; // e.g., 6 for TCP, 17 for UDP
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    static constexpr size_t MIN_SIZE = 20; // Minimum size without options
    size_t get_header_length() const { return (version_ihl & 0x0F) * 4; }
};

// Placeholder for IPv6 Header
struct IPv6Header {
    uint32_t version_tc_flowlabel; // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_length;
    uint8_t next_header; // e.g., 6 for TCP, 17 for UDP
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];

    static constexpr size_t SIZE = 40;
};

// Placeholder for TCP Header
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved_flags; // Data Offset (4 bits), Reserved (3 bits), Flags (9 bits: NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    static constexpr size_t MIN_SIZE = 20; // Minimum size without options
    size_t get_header_length() const { return ((data_offset_reserved_flags & 0xF0) >> 4) * 4; }
};

// Placeholder for UDP Header
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    static constexpr size_t SIZE = 8;
};


class Packet {
public:
    Packet(PacketBuffer* buf) : buffer_(buf), current_offset_(0), l2_header_size_(EthernetHeader::SIZE) {
        if (!buffer_) {
            throw std::invalid_argument("PacketBuffer cannot be null.");
        }
        buffer_->increment_ref();
    }

    ~Packet() {
        if (buffer_) {
            buffer_->decrement_ref();
        }
    }

    // Non-copyable for simplicity, but movable
    Packet(const Packet&) = delete;
    Packet& operator=(const Packet&) = delete;

    Packet(Packet&& other) noexcept : buffer_(other.buffer_), current_offset_(other.current_offset_), l2_header_size_(other.l2_header_size_) {
        other.buffer_ = nullptr; // Prevent double decrement_ref by the moved-from object's destructor
    }

    Packet& operator=(Packet&& other) noexcept {
        if (this != &other) {
            if (buffer_) {
                buffer_->decrement_ref(); // Release own resource
            }
            buffer_ = other.buffer_;
            current_offset_ = other.current_offset_;
            l2_header_size_ = other.l2_header_size_;
            other.buffer_ = nullptr; // Prevent double decrement_ref
        }
        return *this;
    }

    PacketBuffer* get_buffer() const { return buffer_; }

    template <typename HeaderType>
    HeaderType* get_header(size_t offset) const {
        if (!buffer_ || offset + sizeof(HeaderType) > buffer_->get_data_length()) {
            return nullptr; // or throw
        }
        return reinterpret_cast<HeaderType*>(buffer_->get_data_start_ptr() + offset);
    }

    template <typename HeaderType>
    HeaderType* get_header_at_current_offset() const {
        if (!buffer_ || current_offset_ + sizeof(HeaderType) > buffer_->get_data_length()) {
            return nullptr;
        }
        HeaderType* header = reinterpret_cast<HeaderType*>(buffer_->get_data_start_ptr() + current_offset_);
        // Cautiously advance offset ONLY if not a VLAN tag being parsed,
        // as VLAN is a special case for offset management.
        // A more robust parser would advance based on actual header lengths (e.g. IP options)
        // For now, advance by sizeof(HeaderType)
        // current_offset_ += sizeof(HeaderType); // This needs to be managed carefully by specific accessors
        return header;
    }


    EthernetHeader* ethernet() const {
        current_offset_ = 0; // Ethernet is always first
        auto* eth = get_header<EthernetHeader>(current_offset_);
        if (eth) {
            // Check for VLAN tag to correctly set l2_header_size_ for future offsets
            if (ntohs(eth->ethertype) == 0x8100) { // VLAN_ETHERTYPE
                l2_header_size_ = EthernetHeader::SIZE + VlanHeader::SIZE;
            } else {
                l2_header_size_ = EthernetHeader::SIZE;
            }
            // current_offset_ += EthernetHeader::SIZE; // Advance past Ethernet
        }
        return eth;
    }

    VlanHeader* vlan() const {
        // Assumes ethernet() was called first to identify base L2 type
        auto* eth = get_header<EthernetHeader>(0);
        if (eth && ntohs(eth->ethertype) == 0x8100) { // VLAN_ETHERTYPE
            // current_offset_ = EthernetHeader::SIZE; // VLAN is after Ethernet
            return get_header<VlanHeader>(EthernetHeader::SIZE);
        }
        return nullptr;
    }

    // Note: These L3 accessors assume ethernet() and potentially vlan() have been called
    // to set up current_offset_ or determine the L2 framing size.
    IPv4Header* ipv4() const {
        // Determine offset after L2 headers
        current_offset_ = l2_header_size_; // Set current_offset_ to start of L3
        auto* eth = get_header<EthernetHeader>(0);
        if (!eth) return nullptr;

        uint16_t effective_ethertype = ntohs(eth->ethertype);
        if (effective_ethertype == 0x8100) { // VLAN_ETHERTYPE
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == 0x0800) { // IPV4_ETHERTYPE
             IPv4Header* ip_head = get_header<IPv4Header>(current_offset_);
             if (ip_head) current_offset_ += ip_head->get_header_length(); // Advance by actual IP header length
             return ip_head;
        }
        return nullptr;
    }

    IPv6Header* ipv6() const {
        current_offset_ = l2_header_size_; // Set current_offset_ to start of L3
        auto* eth = get_header<EthernetHeader>(0);
        if (!eth) return nullptr;

        uint16_t effective_ethertype = ntohs(eth->ethertype);
        if (effective_ethertype == 0x8100) { // VLAN_ETHERTYPE
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == 0x86DD) { // IPV6_ETHERTYPE
            IPv6Header* ip6_head = get_header<IPv6Header>(current_offset_);
            if (ip6_head) current_offset_ += IPv6Header::SIZE; // Advance by fixed IPv6 header size
            return ip6_head;
        }
        return nullptr;
    }

    TcpHeader* tcp() const {
        // current_offset_ is expected to be at the start of L3 by ipv4() or ipv6()
        // We need to know L3 header size to find the start of L4.
        // So, call ipv4() or ipv6() first, which sets current_offset_ to the start of L4.
        size_t l3_start_offset = l2_header_size_;
        size_t l3_header_length = 0;

        IPv4Header* ip4 = get_header<IPv4Header>(l3_start_offset); // Try IPv4 first
        if (ip4 && ntohs(get_header<EthernetHeader>(0)->ethertype) == 0x0800) { // Check ethertype for IPv4
             if (ip4->protocol == 6) { // TCP_PROTOCOL
                l3_header_length = ip4->get_header_length();
                current_offset_ = l3_start_offset + l3_header_length;
                TcpHeader* tcp_head = get_header<TcpHeader>(current_offset_);
                if (tcp_head) current_offset_ += tcp_head->get_header_length();
                return tcp_head;
            }
        } else {
            IPv6Header* ip6 = get_header<IPv6Header>(l3_start_offset); // Try IPv6
            // Need to check ethertype for IPv6 (via direct eth or vlan)
            uint16_t effective_ethertype = 0;
            auto* eth_check = get_header<EthernetHeader>(0);
            if (eth_check) {
                effective_ethertype = ntohs(eth_check->ethertype);
                if (effective_ethertype == 0x8100) {
                    auto* vlan_check = get_header<VlanHeader>(EthernetHeader::SIZE);
                    if (vlan_check) effective_ethertype = ntohs(vlan_check->ethertype);
                    else effective_ethertype = 0; // Safety
                }
            }

            if (ip6 && effective_ethertype == 0x86DD) { // Check ethertype for IPv6
                if (ip6->next_header == 6) { // TCP_PROTOCOL
                    l3_header_length = IPv6Header::SIZE;
                    current_offset_ = l3_start_offset + l3_header_length;
                    TcpHeader* tcp_head = get_header<TcpHeader>(current_offset_);
                    if (tcp_head) current_offset_ += tcp_head->get_header_length();
                    return tcp_head;
                }
            }
        }
        // Restore offset if not TCP or if L3 header was not found correctly
        // current_offset_ = l3_start_offset; // This would be incorrect as ipv4/ipv6 might have advanced it.
        // It's better to ensure current_offset_ is only advanced upon successful header retrieval.
        return nullptr;
    }

    UdpHeader* udp() const {
        size_t l3_start_offset = l2_header_size_;
        size_t l3_header_length = 0;

        IPv4Header* ip4 = get_header<IPv4Header>(l3_start_offset); // Try IPv4 first
        if (ip4 && ntohs(get_header<EthernetHeader>(0)->ethertype) == 0x0800) { // Check ethertype for IPv4
            if (ip4->protocol == 17) { // UDP_PROTOCOL
                l3_header_length = ip4->get_header_length();
                current_offset_ = l3_start_offset + l3_header_length;
                UdpHeader* udp_head = get_header<UdpHeader>(current_offset_);
                if (udp_head) current_offset_ += UdpHeader::SIZE;
                return udp_head;
            }
        } else {
            IPv6Header* ip6 = get_header<IPv6Header>(l3_start_offset); // Try IPv6
            uint16_t effective_ethertype = 0;
            auto* eth_check = get_header<EthernetHeader>(0);
            if (eth_check) {
                effective_ethertype = ntohs(eth_check->ethertype);
                if (effective_ethertype == 0x8100) { // VLAN
                    auto* vlan_check = get_header<VlanHeader>(EthernetHeader::SIZE);
                    if (vlan_check) effective_ethertype = ntohs(vlan_check->ethertype);
                     else effective_ethertype = 0; // Safety
                }
            }

            if (ip6 && effective_ethertype == 0x86DD) { // Check ethertype for IPv6
                if (ip6->next_header == 17) { // UDP_PROTOCOL
                    l3_header_length = IPv6Header::SIZE;
                    current_offset_ = l3_start_offset + l3_header_length;
                    UdpHeader* udp_head = get_header<UdpHeader>(current_offset_);
                    if (udp_head) current_offset_ += UdpHeader::SIZE;
                    return udp_head;
                }
            }
        }
        // current_offset_ = l3_start_offset; // Similar to TCP, avoid incorrect reset.
        return nullptr;
    }

    // L2 Methods
    bool has_vlan() const {
        auto* eth = ethernet(); // This also recalculates l2_header_size_
        return eth && ntohs(eth->ethertype) == 0x8100; // VLAN_ETHERTYPE
    }

    std::optional<uint16_t> vlan_id() const {
        if (has_vlan()) { // has_vlan calls ethernet() which sets up l2_header_size_
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (vlan_hdr) {
                return vlan_hdr->get_vlan_id();
            }
        }
        return std::nullopt;
    }

    std::optional<uint8_t> vlan_priority() const {
        if (has_vlan()) {
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (vlan_hdr) {
                return vlan_hdr->get_priority();
            }
        }
        return std::nullopt;
    }

    std::optional<MacAddress> src_mac() const {
        auto* eth = ethernet();
        if (eth) {
            return eth->src_mac;
        }
        return std::nullopt;
    }

    std::optional<MacAddress> dst_mac() const {
        auto* eth = ethernet();
        if (eth) {
            return eth->dst_mac;
        }
        return std::nullopt;
    }

    // Packet Manipulation
    bool set_dst_mac(const MacAddress& mac) {
        auto* eth = ethernet();
        if (eth) {
            eth->dst_mac = mac;
            return true;
        }
        return false;
    }

    // Pushes a new VLAN tag. Assumes buffer has space at the current data start + EthernetHeader::SIZE.
    // This is a complex operation as it requires shifting data.
    // A simpler version might only work if there's pre-allocated headroom.
    // For now, let's assume we need to make space if not already VLAN tagged.
    // IMPORTANT: This operation assumes that the underlying PacketBuffer has enough
    // capacity beyond buffer_->get_data_length() to accommodate the new VLAN header.
    // If buffer_->get_data_length() represents the full capacity, this operation is unsafe
    // and may lead to buffer overflows. Proper capacity management in PacketBuffer
    // is crucial for the safety of this method.
    bool push_vlan(uint16_t vlan_id_val, uint8_t priority = 0) {
        if (!buffer_ || buffer_->get_data_length() < EthernetHeader::SIZE) return false;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->get_data_start_ptr());
        uint16_t original_ethertype = eth->ethertype; // Already in network byte order

        if (has_vlan()) { // Already has a VLAN tag, modify it
             VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->get_data_start_ptr() + EthernetHeader::SIZE);
             vlan_hdr->set_vlan_id(vlan_id_val);
             vlan_hdr->set_priority(priority);
             // ethertype after vlan tag remains the same
        } else { // No VLAN tag, insert one
            // Check if there's enough tailroom in the buffer structure to add a VLAN header,
            // or if we can expand the data length if there's overall capacity.
            // The original logic shifted data; PacketBuffer's prepend_data is not quite right here
            // as we are inserting *after* the Ethernet header but before L3.

            // We need to make space *within* the current data area, or ensure buffer has total capacity.
            if (buffer_->get_tailroom() < VlanHeader::SIZE) {
                // This check is simplified. A more robust check would consider if the *total* buffer capacity
                // (not just tailroom from current data_len) is sufficient.
                // If prepend_data or similar methods are used, they check headroom/tailroom.
                // Here, we are inserting in the middle, so it's more complex.
                // For now, assume if not enough tailroom to just expand data_len, it might fail.
                // A better way is to check if buffer_->get_capacity() is enough for current_len + VlanHeader::SIZE
                 if (buffer_->get_data_length() + VlanHeader::SIZE > buffer_->get_capacity()) {
                    return false; // Not enough overall capacity to expand data into tailroom
                 }
            }


            // Pointer to the start of L3 data (payload after Ethernet header)
            unsigned char* l3_start = buffer_->get_data_start_ptr() + EthernetHeader::SIZE;
            size_t l3_len = buffer_->get_data_length() - EthernetHeader::SIZE;

            // Shift L3 data to make space for VLAN header
            // memmove is safe for overlapping regions
            memmove(l3_start + VlanHeader::SIZE, l3_start, l3_len);

            // Insert VLAN header
            VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(l3_start);
            vlan_hdr->tci = 0; // Clear it first
            vlan_hdr->set_vlan_id(vlan_id_val);
            vlan_hdr->set_priority(priority);
            vlan_hdr->ethertype = original_ethertype; // Original L2 ethertype moves here

            // Update Ethernet header's ethertype to indicate VLAN
            eth->ethertype = htons(0x8100); // VLAN_ETHERTYPE

            // Update packet's internal state: increase data length in buffer
            if (!buffer_->set_data_len(buffer_->get_data_length() + VlanHeader::SIZE)) {
                // This should not happen if capacity check above was okay, but as a safeguard:
                // Attempt to revert memmove? Very tricky. Best to ensure checks are perfect.
                // Or, the initial capacity check should be definitive.
                return false;
            }
            l2_header_size_ += VlanHeader::SIZE;
        }
        update_checksums();
        return true;
    }

    bool pop_vlan() {
        if (!has_vlan()) { // has_vlan calls ethernet()
            return false; // No VLAN tag to pop
        }
        // Ensure buffer has at least Ethernet + VLAN header
        if (!buffer_ || buffer_->get_data_length() < EthernetHeader::SIZE + VlanHeader::SIZE) return false;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->get_data_start_ptr());
        VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->get_data_start_ptr() + EthernetHeader::SIZE);

        uint16_t new_ethertype = vlan_hdr->ethertype; // This is the ethertype that was after the VLAN tag

        unsigned char* vlan_header_start_ptr = buffer_->get_data_start_ptr() + EthernetHeader::SIZE;
        unsigned char* payload_after_vlan_start_ptr = vlan_header_start_ptr + VlanHeader::SIZE;
        size_t payload_size = buffer_->get_data_length() - (EthernetHeader::SIZE + VlanHeader::SIZE);

        // Shift payload data left to overwrite VLAN header
        memmove(vlan_header_start_ptr, payload_after_vlan_start_ptr, payload_size);

        // Update Ethernet header's ethertype
        eth->ethertype = new_ethertype; // Restore original ethertype

        // Update packet's internal state: decrease data length in buffer
        if (!buffer_->set_data_len(buffer_->get_data_length() - VlanHeader::SIZE)) {
            // Should not happen if initial length check was okay.
            return false;
        }
        l2_header_size_ -= VlanHeader::SIZE;

        update_checksums();
        return true;
    }


    // Placeholder for checksum updates (e.g., IP, TCP/UDP)
    // void update_checksums() { // Ensuring the old placeholder is fully removed or commented out
    //     // This would involve recalculating checksums for IP, TCP, UDP
    //     // if their headers or payloads have changed.
    // } // End of old placeholder
    // The actual implementation starts below:

    void update_checksums() {
        if (!buffer_) return;

        // Determine L2 header size first. Call ethernet() to ensure l2_header_size_ is set.
        // We don't strictly need the eth_hdr pointer here unless we check ethertype directly,
        // but calling ethernet() initializes l2_header_size_ which is crucial.
        ethernet(); // This sets l2_header_size_ correctly, considering VLAN.
        size_t current_l2_header_size = l2_header_size_; // Use a local copy

        IPv4Header* ip4_hdr = get_header<IPv4Header>(current_l2_header_size);
        IPv6Header* ip6_hdr = nullptr;
        uint8_t l3_protocol = 0;
        size_t l3_header_length = 0;
        size_t l4_offset = 0;

        // Check for IPv4
        if (ip4_hdr && ( (ip4_hdr->version_ihl & 0xF0) >> 4 ) == 4) { // Basic validation for IPv4
            l3_protocol = ip4_hdr->protocol;
            l3_header_length = ip4_hdr->get_header_length();
            l4_offset = current_l2_header_size + l3_header_length;

            // IPv4 Header Checksum
            ip4_hdr->header_checksum = 0; // Zero out checksum field
            ip4_hdr->header_checksum = calculate_checksum(reinterpret_cast<const uint8_t*>(ip4_hdr), l3_header_length);
        } else {
            // If not IPv4, try IPv6
            ip4_hdr = nullptr; // Not a valid IPv4 packet for our purposes
            ip6_hdr = get_header<IPv6Header>(current_l2_header_size);
            if (ip6_hdr && ( (ntohl(ip6_hdr->version_tc_flowlabel) & 0xF0000000) >> 28 ) == 6) { // Basic validation for IPv6
                l3_protocol = ip6_hdr->next_header;
                l3_header_length = IPv6Header::SIZE; // IPv6 header has fixed size
                l4_offset = current_l2_header_size + l3_header_length;
            } else {
                ip6_hdr = nullptr; // Not a valid IPv6 packet
                return; // Not IPv4 or IPv6, nothing more to do
            }
        }

        TcpHeader* tcp_hdr = nullptr;
        UdpHeader* udp_hdr = nullptr;
        const uint8_t* l4_payload_ptr = nullptr;
        size_t l4_payload_len = 0;

        if (l3_protocol == 6) { // TCP
            tcp_hdr = get_header<TcpHeader>(l4_offset);
            if (tcp_hdr) {
                size_t tcp_header_len = tcp_hdr->get_header_length();
                uint16_t tcp_segment_total_len; // TCP Header + TCP Data

                if (ip4_hdr) {
                    // Total length of IP packet (L3 header + L3 payload) minus IP header length
                    if (ntohs(ip4_hdr->total_length) < l3_header_length) return; // Invalid IP total length
                    tcp_segment_total_len = ntohs(ip4_hdr->total_length) - l3_header_length;
                } else if (ip6_hdr) {
                    // IPv6 payload_length is exactly the TCP header + TCP data length
                    tcp_segment_total_len = ntohs(ip6_hdr->payload_length);
                } else { return; } // Should not happen

                if (tcp_segment_total_len < tcp_header_len) return; // Invalid TCP segment length

                l4_payload_len = tcp_segment_total_len - tcp_header_len;
                l4_payload_ptr = buffer_->get_data_start_ptr() + l4_offset + tcp_header_len;

                // Boundary check for payload: ensure payload defined by IP/TCP headers fits in buffer's data length
                if ((l4_offset + tcp_header_len + l4_payload_len) > buffer_->get_data_length()) {
                    // Calculated payload extends beyond the actual data in the buffer.
                    // This indicates a malformed packet or inconsistent lengths.
                    return;
                }

                // TCP Checksum calculation
                tcp_hdr->checksum = 0;

                std::vector<uint8_t> pseudo_header_plus_tcp;
                // Max pseudo header size (IPv6: 40B) + TCP segment total length
                pseudo_header_plus_tcp.reserve(40 + tcp_segment_total_len);

                if (ip4_hdr) {
                    // IPv4 Pseudo Header
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(&ip4_hdr->src_ip), reinterpret_cast<uint8_t*>(&ip4_hdr->src_ip) + 4);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(&ip4_hdr->dst_ip), reinterpret_cast<uint8_t*>(&ip4_hdr->dst_ip) + 4);
                    pseudo_header_plus_tcp.push_back(0); // Zero
                    pseudo_header_plus_tcp.push_back(ip4_hdr->protocol); // Protocol
                    uint16_t tcp_len_be = htons(tcp_segment_total_len); // Use corrected total length for TCP segment
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(&tcp_len_be), reinterpret_cast<uint8_t*>(&tcp_len_be) + 2);
                } else if (ip6_hdr) {
                    // IPv6 Pseudo Header
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), &ip6_hdr->src_ip[0], &ip6_hdr->src_ip[0] + 16);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), &ip6_hdr->dst_ip[0], &ip6_hdr->dst_ip[0] + 16);
                    uint32_t tcp_len_be32 = htonl(tcp_segment_total_len); // Use corrected total length for TCP segment
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(&tcp_len_be32), reinterpret_cast<uint8_t*>(&tcp_len_be32) + 4);
                    pseudo_header_plus_tcp.push_back(0); // Zeros
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(ip6_hdr->next_header); // Next Header
                }

                // Append TCP header and payload
                pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(tcp_hdr), reinterpret_cast<uint8_t*>(tcp_hdr) + tcp_header_len);
                if (l4_payload_len > 0 && l4_payload_ptr) {
                     pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), l4_payload_ptr, l4_payload_ptr + l4_payload_len);
                }
                tcp_hdr->checksum = calculate_checksum(pseudo_header_plus_tcp.data(), pseudo_header_plus_tcp.size());
            }
        } else if (l3_protocol == 17) { // UDP
            udp_hdr = get_header<UdpHeader>(l4_offset);
            if (udp_hdr) {
                size_t udp_header_len = UdpHeader::SIZE; // Fixed size
                uint16_t udp_total_len_from_header = ntohs(udp_hdr->length); // Includes UDP header and payload

                if (udp_total_len_from_header < udp_header_len) return; // Invalid UDP length
                l4_payload_len = udp_total_len_from_header - udp_header_len;
                l4_payload_ptr = buffer_->get_data_start_ptr() + l4_offset + udp_header_len;

                // Boundary check for payload: ensure payload defined by UDP header fits in buffer's data length
                if ((l4_offset + udp_header_len + l4_payload_len) > buffer_->get_data_length()) {
                    // Calculated payload extends beyond the actual data in the buffer.
                    return;
                }

                // UDP Checksum calculation
                udp_hdr->checksum = 0;

                std::vector<uint8_t> pseudo_header_plus_udp;
                // Max pseudo header (IPv6: 40B) + UDP total length from header
                pseudo_header_plus_udp.reserve(40 + udp_total_len_from_header);

                if (ip4_hdr) {
                    // IPv4 Pseudo Header
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(&ip4_hdr->src_ip), reinterpret_cast<uint8_t*>(&ip4_hdr->src_ip) + 4);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(&ip4_hdr->dst_ip), reinterpret_cast<uint8_t*>(&ip4_hdr->dst_ip) + 4);
                    pseudo_header_plus_udp.push_back(0); // Zero
                    pseudo_header_plus_udp.push_back(ip4_hdr->protocol); // Protocol
                    uint16_t udp_len_be = htons(udp_total_len_from_header); // Use UDP length from UDP header
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(&udp_len_be), reinterpret_cast<uint8_t*>(&udp_len_be) + 2);
                } else if (ip6_hdr) {
                    // IPv6 Pseudo Header
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), &ip6_hdr->src_ip[0], &ip6_hdr->src_ip[0] + 16);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), &ip6_hdr->dst_ip[0], &ip6_hdr->dst_ip[0] + 16);
                    uint32_t udp_len_be32 = htonl(udp_total_len_from_header); // Upper-layer packet length
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(&udp_len_be32), reinterpret_cast<uint8_t*>(&udp_len_be32) + 4);
                    pseudo_header_plus_udp.push_back(0); // Zeros
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(ip6_hdr->next_header); // Next Header
                }

                // Append UDP header and payload
                pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(udp_hdr), reinterpret_cast<uint8_t*>(udp_hdr) + udp_header_len);
                if (l4_payload_len > 0 && l4_payload_ptr) {
                     pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), l4_payload_ptr, l4_payload_ptr + l4_payload_len);
                }

                uint16_t calculated_udp_checksum = calculate_checksum(pseudo_header_plus_udp.data(), pseudo_header_plus_udp.size());

                // For UDP over IPv4, if checksum is 0, it should be transmitted as 0xFFFF.
                // For UDP over IPv6, checksum is mandatory and if 0, transmitted as 0xFFFF.
                if (calculated_udp_checksum == 0) {
                    udp_hdr->checksum = 0xFFFF;
                } else {
                    udp_hdr->checksum = calculated_udp_checksum;
                }
                // If UDP over IPv4 and checksum is not computed (optional), it can be zero.
                // Here we always compute it. If it's IPv4 and the original packet had a zero checksum
                // (meaning it was not computed by the sender), this will now add a checksum.
                // This is generally fine and often recommended.
            }
        }
    }

private:
    // Generic checksum calculation (RFC 1071)
    // Calculates the checksum for the given data.
    // Returns the checksum in network byte order.
    static uint16_t calculate_checksum(const uint8_t* data, size_t len) {
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

        while (len > 1) {
            sum += ntohs(*ptr++); // Sum in host byte order
            len -= 2;
        }

        // If there's an odd byte left, pad it with zero for checksum calculation
        if (len > 0) {
            sum += ntohs(static_cast<uint16_t>(*reinterpret_cast<const uint8_t*>(ptr)) << 8);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return htons(static_cast<uint16_t>(~sum));
    }

    PacketBuffer* buffer_;
    mutable size_t current_offset_; // Tracks the current position while parsing headers sequentially
    mutable size_t l2_header_size_; // Stores the size of L2 headers (Ethernet + potentially VLAN)

    // Hypothetical member for actual allocated capacity if different from buffer_->size
    // This is needed for safe push_vlan like operations.
    // size_t data_capacity_placeholder;
}; // Semicolon was correctly here from previous fix attempt.

} // namespace netflow

#endif // NETFLOW_PACKET_HPP
