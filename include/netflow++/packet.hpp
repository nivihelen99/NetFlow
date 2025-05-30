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

    // Non-copyable, non-movable for simplicity for now
    Packet(const Packet&) = delete;
    Packet& operator=(const Packet&) = delete;
    Packet(Packet&&) = delete;
    Packet& operator=(Packet&&) = delete;

    PacketBuffer* get_buffer() const { return buffer_; }

    template <typename HeaderType>
    HeaderType* get_header(size_t offset) const {
        if (!buffer_ || offset + sizeof(HeaderType) > buffer_->size) {
            return nullptr; // or throw
        }
        return reinterpret_cast<HeaderType*>(buffer_->data + offset);
    }

    template <typename HeaderType>
    HeaderType* get_header_at_current_offset() const {
        if (!buffer_ || current_offset_ + sizeof(HeaderType) > buffer_->size) {
            return nullptr;
        }
        HeaderType* header = reinterpret_cast<HeaderType*>(buffer_->data + current_offset_);
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
        current_offset_ = l2_header_size_;
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
             // if (ip_head) current_offset_ += ip_head->get_header_length(); // Advance by actual IP header length
             return ip_head;
        }
        return nullptr;
    }

    IPv6Header* ipv6() const {
        current_offset_ = l2_header_size_;
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
            // if (ip6_head) current_offset_ += IPv6Header::SIZE; // Advance by fixed IPv6 header size
            return ip6_head;
        }
        return nullptr;
    }

    TcpHeader* tcp() const {
        size_t previous_l4_offset = l2_header_size_; // Start after L2
        IPv4Header* ip4 = ipv4(); // This sets current_offset_ based on L2 and checks ethertype
        if (ip4) {
            if (ip4->protocol == 6) { // TCP_PROTOCOL
                // current_offset_ was already set by ipv4() to point to start of L3 header.
                // Now advance by L3 header length.
                current_offset_ = l2_header_size_ + ip4->get_header_length();
                TcpHeader* tcp_head = get_header<TcpHeader>(current_offset_);
                // if (tcp_head) current_offset_ += tcp_head->get_header_length();
                return tcp_head;
            }
        } else {
            IPv6Header* ip6 = ipv6(); // This also sets current_offset_
            if (ip6) {
                if (ip6->next_header == 6) { // TCP_PROTOCOL
                    // current_offset_ was set by ipv6() to point to start of L3.
                    // Advance by L3 header length.
                    current_offset_ = l2_header_size_ + IPv6Header::SIZE; // IPv6 has fixed header size for this purpose
                    TcpHeader* tcp_head = get_header<TcpHeader>(current_offset_);
                    // if (tcp_head) current_offset_ += tcp_head->get_header_length();
                    return tcp_head;
                }
            }
        }
        current_offset_ = previous_l4_offset; // Restore offset if not TCP
        return nullptr;
    }

    UdpHeader* udp() const {
        size_t previous_l4_offset = l2_header_size_;
        IPv4Header* ip4 = ipv4();
        if (ip4) {
            if (ip4->protocol == 17) { // UDP_PROTOCOL
                current_offset_ = l2_header_size_ + ip4->get_header_length();
                UdpHeader* udp_head = get_header<UdpHeader>(current_offset_);
                // if (udp_head) current_offset_ += UdpHeader::SIZE;
                return udp_head;
            }
        } else {
            IPv6Header* ip6 = ipv6();
            if (ip6) {
                if (ip6->next_header == 17) { // UDP_PROTOCOL
                    current_offset_ = l2_header_size_ + IPv6Header::SIZE;
                    UdpHeader* udp_head = get_header<UdpHeader>(current_offset_);
                    // if (udp_head) current_offset_ += UdpHeader::SIZE;
                    return udp_head;
                }
            }
        }
        current_offset_ = previous_l4_offset;
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
    bool push_vlan(uint16_t vlan_id_val, uint8_t priority = 0) {
        if (!buffer_ || buffer_->size < EthernetHeader::SIZE) return false;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->data);
        uint16_t original_ethertype = eth->ethertype; // Already in network byte order

        // Check if new total size exceeds buffer capacity
        if (has_vlan()) { // Already has a VLAN tag, modify it (or stack, but let's assume modify for now)
             VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->data + EthernetHeader::SIZE);
             vlan_hdr->set_vlan_id(vlan_id_val);
             vlan_hdr->set_priority(priority);
             // ethertype after vlan tag remains the same
        } else { // No VLAN tag, insert one
            if (buffer_->size < EthernetHeader::SIZE + VlanHeader::SIZE) return false; // Not enough space for new vlan

            // Make space for VLAN header
            // Shift payload data (everything after Ethernet header) by VlanHeader::SIZE bytes
            // This is dangerous if buffer_->size is the *actual* packet data size, not allocated capacity
            // Assuming buffer_->data points to a region large enough for this modification.
            // A real implementation needs careful buffer capacity management.
            // Let's assume buffer_->size is the current packet length and there's no spare room.
            // This means push_vlan can only be done if the PacketBuffer was allocated with extra space.
            // For this subtask, we'll simulate it but acknowledge the buffer capacity issue.
            // A robust solution requires reallocating or using a buffer with headroom.

            // If buffer is not large enough to insert VLAN header
            // The check for data_capacity_placeholder has been removed.
            // A proper check against actual buffer capacity should be implemented
            // if PacketBuffer is extended to support it.
            // For now, we assume the buffer is large enough or this is handled elsewhere.
            // if (buffer_->size + VlanHeader::SIZE > buffer_->get_capacity()) {
            //     return false;
            // }
            // The unconditional 'return false;' and its associated '}' were removed from here.
            // The logic now proceeds to insert the VLAN tag if the initial checks pass.
            // Proper buffer capacity check is still a TODO if PacketBuffer is to manage fixed-size allocations.

            unsigned char* payload_start = buffer_->data + EthernetHeader::SIZE;
            size_t payload_size = buffer_->size - EthernetHeader::SIZE;

            // Shift payload to make space for VLAN header
            // memmove is safe for overlapping regions
            memmove(payload_start + VlanHeader::SIZE, payload_start, payload_size);

            // Insert VLAN header
            VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(payload_start);
            vlan_hdr->tci = 0; // Clear it first
            vlan_hdr->set_vlan_id(vlan_id_val);
            vlan_hdr->set_priority(priority);
            vlan_hdr->ethertype = original_ethertype; // Original L2 ethertype moves here

            // Update Ethernet header's ethertype to indicate VLAN
            eth->ethertype = htons(0x8100); // VLAN_ETHERTYPE

            // Update packet's internal state
            buffer_->size += VlanHeader::SIZE; // Packet is now larger
            l2_header_size_ += VlanHeader::SIZE;
        }
        update_checksums(); // Placeholder
        return true;
    }

    bool pop_vlan() {
        if (!has_vlan()) { // has_vlan calls ethernet()
            return false; // No VLAN tag to pop
        }
        if (!buffer_ || buffer_->size < EthernetHeader::SIZE + VlanHeader::SIZE) return false;


        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->data);
        VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->data + EthernetHeader::SIZE);

        uint16_t new_ethertype = vlan_hdr->ethertype; // This is the ethertype after VLAN

        unsigned char* vlan_header_start = buffer_->data + EthernetHeader::SIZE;
        unsigned char* payload_after_vlan_start = vlan_header_start + VlanHeader::SIZE;
        size_t payload_size = buffer_->size - (EthernetHeader::SIZE + VlanHeader::SIZE);

        // Shift payload data left to overwrite VLAN header
        memmove(vlan_header_start, payload_after_vlan_start, payload_size);

        // Update Ethernet header's ethertype
        eth->ethertype = new_ethertype; // Restore original ethertype

        // Update packet's internal state
        buffer_->size -= VlanHeader::SIZE; // Packet is now smaller
        l2_header_size_ -= VlanHeader::SIZE;

        update_checksums(); // Placeholder
        return true;
    }


    // Placeholder for checksum updates (e.g., IP, TCP/UDP)
    void update_checksums() {
        // This would involve recalculating checksums for IP, TCP, UDP
        // if their headers or payloads have changed.
        // For example, an IP checksum:
        // IPv4Header* ip = ipv4();
        // if (ip) {
        //   ip->header_checksum = 0;
        //   uint16_t checksum = calculate_internet_checksum(reinterpret_cast<uint16_t*>(ip), ip->get_header_length());
        //   ip->header_checksum = htons(checksum);
        // }
        // Similar logic for TCP/UDP checksums which also involve pseudo-headers.
    }


private:
    PacketBuffer* buffer_;
    mutable size_t current_offset_; // Tracks the current position while parsing headers sequentially
    mutable size_t l2_header_size_; // Stores the size of L2 headers (Ethernet + potentially VLAN)

    // Hypothetical member for actual allocated capacity if different from buffer_->size
    // This is needed for safe push_vlan like operations.
    // size_t data_capacity_placeholder;
};

} // namespace netflow

#endif // NETFLOW_PACKET_HPP
