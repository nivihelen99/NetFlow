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
// Ensure MacAddress is packed for correct on-wire representation if not already.
// For network headers, packing is crucial. Using pragma pack for wider compatibility.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct MacAddress {
    uint8_t bytes[6];
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

    MacAddress() {
        std::fill(bytes, bytes + 6, 0);
    }

    // Removed duplicate constructor

    MacAddress(const uint8_t* mac_bytes) {
        std::copy(mac_bytes, mac_bytes + 6, bytes);
    }

    bool operator==(const MacAddress& other) const {
        return std::equal(bytes, bytes + 6, other.bytes);
    }
};

// Define EtherTypes
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

// Define IP Protocol Numbers
constexpr uint8_t IPPROTO_ICMP = 1;
constexpr uint8_t IPPROTO_TCP = 6;
constexpr uint8_t IPPROTO_UDP = 17;


// Placeholder for Ethernet Header
// Ensure EthernetHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct EthernetHeader {
    MacAddress dst_mac;
    MacAddress src_mac;
    uint16_t ethertype; // e.g., ETHERTYPE_IPV4, ETHERTYPE_VLAN, ETHERTYPE_IPV6

    static constexpr size_t SIZE = sizeof(MacAddress) * 2 + sizeof(uint16_t);
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Placeholder for VLAN Header (802.1Q)
// Ensure VlanHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct VlanHeader {
    uint16_t tci; // Tag Control Information (PCP: 3 bits, DEI: 1 bit, VID: 12 bits)
    uint16_t ethertype;

    static constexpr size_t SIZE = sizeof(uint16_t) * 2;
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

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
// Ensure LLCHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct LLCHeader {
    uint8_t dsap;      // Destination Service Access Point
    uint8_t ssap;      // Source Service Access Point
    uint8_t control;   // Control field
    // For STP BPDUs, DSAP and SSAP are often 0x42, Control is 0x03 (UI frame)
    static constexpr size_t SIZE = 3;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Placeholder for IPv4 Header
// Ensure IPv4Header is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
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
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Placeholder for IPv6 Header
// Ensure IPv6Header is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct IPv6Header {
    uint32_t version_tc_flowlabel; // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_length;
    uint8_t next_header; // e.g., 6 for TCP, 17 for UDP
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];

    static constexpr size_t SIZE = 40;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Placeholder for TCP Header
// Ensure TcpHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
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
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Placeholder for UDP Header
// Ensure UdpHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    static constexpr size_t SIZE = 8;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// Define IpAddress as uint32_t for IPv4
using IpAddress = uint32_t;

// Helper function to convert an IpAddress subnet mask to its prefix length (e.g., 255.255.255.0 -> 24)
uint8_t ip_mask_to_prefix_length(IpAddress subnet_mask);


// ARP Header Structure
// Ensure ArpHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct ArpHeader {
    uint16_t hardware_type;     // e.g., 1 for Ethernet
    uint16_t protocol_type;     // e.g., ETHERTYPE_IPV4 for IPv4
    uint8_t  hardware_addr_len; // e.g., 6 for MAC address
    uint8_t  protocol_addr_len; // e.g., 4 for IPv4
    uint16_t opcode;            // e.g., 1 for ARP request, 2 for ARP reply
    MacAddress sender_mac;
    IpAddress  sender_ip;       // Using IpAddress = uint32_t
    MacAddress target_mac;
    IpAddress  target_ip;       // Using IpAddress = uint32_t

    static constexpr size_t SIZE = 2 * sizeof(uint16_t) + 2 * sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(MacAddress) + 2 * sizeof(IpAddress);
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

// ICMP Header Structure (basic, focusing on Echo request/reply)
// Ensure IcmpHeader is packed.
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier; // For Echo request/reply (optional, may be zero)
    uint16_t sequence_number; // For Echo request/reply (optional, may be zero)

    // Common ICMP types
    static constexpr uint8_t TYPE_ECHO_REPLY = 0;
    static constexpr uint8_t TYPE_ECHO_REQUEST = 8;
    // Other types like Destination Unreachable (3), Redirect (5), etc.

    static constexpr size_t MIN_SIZE = sizeof(uint8_t) * 2 + sizeof(uint16_t) * 3; // For Echo
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif


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
            if (ntohs(eth->ethertype) == ETHERTYPE_VLAN) {
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
        if (eth && ntohs(eth->ethertype) == ETHERTYPE_VLAN) {
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
        if (effective_ethertype == ETHERTYPE_VLAN) {
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) {
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
        if (effective_ethertype == ETHERTYPE_VLAN) {
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV6) {
            IPv6Header* ip6_head = get_header<IPv6Header>(current_offset_);
            if (ip6_head) current_offset_ += IPv6Header::SIZE; // Advance by fixed IPv6 header size
            return ip6_head;
        }
        return nullptr;
    }

    TcpHeader* tcp() const {
        // Ensure l2_header_size_ is up-to-date by calling ethernet()
        // This is okay because ethernet() is const and idempotent for this purpose.
        ethernet(); // Sets l2_header_size_ correctly, considering VLAN

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr; // No Ethernet header, cannot proceed

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr; // Should not happen if ethertype is VLAN
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) { // IPv4
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_TCP) { // TCP_PROTOCOL
                size_t l4_offset = l2_header_size_ + ip4->get_header_length();
                TcpHeader* tcp_head = get_header<TcpHeader>(l4_offset);
                // if (tcp_head) current_offset_ = l4_offset + tcp_head->get_header_length(); // Manage current_offset_ if needed
                return tcp_head;
            }
        } else if (effective_ethertype == ETHERTYPE_IPV6) { // IPv6
            IPv6Header* ip6 = get_header<IPv6Header>(l2_header_size_);
            if (ip6 && ip6->next_header == IPPROTO_TCP) { // TCP_PROTOCOL
                size_t l4_offset = l2_header_size_ + IPv6Header::SIZE; // IPv6 header size is fixed
                TcpHeader* tcp_head = get_header<TcpHeader>(l4_offset);
                // if (tcp_head) current_offset_ = l4_offset + tcp_head->get_header_length(); // Manage current_offset_
                return tcp_head;
            }
        }
        return nullptr;
    }

    UdpHeader* udp() const {
        ethernet(); // Sets l2_header_size_ correctly

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr;

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr;
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) { // IPv4
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_UDP) { // UDP_PROTOCOL
                size_t l4_offset = l2_header_size_ + ip4->get_header_length();
                UdpHeader* udp_head = get_header<UdpHeader>(l4_offset);
                // if (udp_head) current_offset_ = l4_offset + UdpHeader::SIZE; // Manage current_offset_
                return udp_head;
            }
        } else if (effective_ethertype == ETHERTYPE_IPV6) { // IPv6
            IPv6Header* ip6 = get_header<IPv6Header>(l2_header_size_);
            if (ip6 && ip6->next_header == IPPROTO_UDP) { // UDP_PROTOCOL
                size_t l4_offset = l2_header_size_ + IPv6Header::SIZE;
                UdpHeader* udp_head = get_header<UdpHeader>(l4_offset);
                // if (udp_head) current_offset_ = l4_offset + UdpHeader::SIZE; // Manage current_offset_
                return udp_head;
            }
        }
        return nullptr;
    }

    // L2 Methods (This brace was prematurely closing the class)
    // }; // This was the incorrect closing brace for Packet class

    // Method to access ArpHeader
    ArpHeader* arp() const {
        ethernet(); // Ensure l2_header_size_ is set
        current_offset_ = l2_header_size_; // ARP is an L2.5/L3 protocol, typically follows Ethernet/VLAN
        auto* eth = get_header<EthernetHeader>(0);
        if (!eth) return nullptr;

        uint16_t effective_ethertype = ntohs(eth->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_ARP) {
            ArpHeader* arp_head = get_header<ArpHeader>(current_offset_);
            // if (arp_head) current_offset_ += ArpHeader::SIZE; // Advance offset if needed
            return arp_head;
        }
        return nullptr;
    }

    // Method to access IcmpHeader
    IcmpHeader* icmp() const {
        ethernet(); // Ensure l2_header_size_ is set

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr;

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr;
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) { // ICMP typically over IPv4
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_ICMP) {
                size_t icmp_offset = l2_header_size_ + ip4->get_header_length();
                IcmpHeader* icmp_head = get_header<IcmpHeader>(icmp_offset);
                // if (icmp_head) current_offset_ = icmp_offset + IcmpHeader::MIN_SIZE; // Or actual size if known
                return icmp_head;
            }
        } else if (effective_ethertype == ETHERTYPE_IPV6) { // ICMPv6
            IPv6Header* ip6 = get_header<IPv6Header>(l2_header_size_);
            // Note: ICMPv6 has a different protocol number (58) and structure.
            // This method currently targets ICMPv4 due to IPPROTO_ICMP being 1.
            // For ICMPv6, a different check (ip6->next_header == 58) and potentially
            // a different Icmpv6Header struct would be needed.
            // The current IcmpHeader is for ICMPv4.
        }
        return nullptr;
    }


    // L2 Methods
    bool has_vlan() const {
        auto* eth = ethernet(); // This also recalculates l2_header_size_
        return eth && ntohs(eth->ethertype) == ETHERTYPE_VLAN;
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

    bool push_vlan(uint16_t vlan_id_val, uint8_t priority = 0) {
        if (!buffer_ || buffer_->get_data_length() < EthernetHeader::SIZE) return false;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->get_data_start_ptr());
        uint16_t original_ethertype = eth->ethertype;

        if (has_vlan()) {
             VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->get_data_start_ptr() + EthernetHeader::SIZE);
             vlan_hdr->set_vlan_id(vlan_id_val);
             vlan_hdr->set_priority(priority);
        } else {
            if (buffer_->get_tailroom() < VlanHeader::SIZE) {
                 if (buffer_->get_data_length() + VlanHeader::SIZE > buffer_->get_capacity()) {
                    return false;
                 }
            }

            unsigned char* l3_start = buffer_->get_data_start_ptr() + EthernetHeader::SIZE;
            size_t l3_len = buffer_->get_data_length() - EthernetHeader::SIZE;

            memmove(l3_start + VlanHeader::SIZE, l3_start, l3_len);

            VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(l3_start);
            vlan_hdr->tci = 0;
            vlan_hdr->set_vlan_id(vlan_id_val);
            vlan_hdr->set_priority(priority);
            vlan_hdr->ethertype = original_ethertype;

            eth->ethertype = htons(ETHERTYPE_VLAN);

            if (!buffer_->set_data_len(buffer_->get_data_length() + VlanHeader::SIZE)) {
                return false;
            }
            l2_header_size_ += VlanHeader::SIZE;
        }
        update_checksums();
        return true;
    }

    bool pop_vlan() {
        if (!has_vlan()) {
            return false;
        }
        if (!buffer_ || buffer_->get_data_length() < EthernetHeader::SIZE + VlanHeader::SIZE) return false;

        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer_->get_data_start_ptr());
        VlanHeader* vlan_hdr = reinterpret_cast<VlanHeader*>(buffer_->get_data_start_ptr() + EthernetHeader::SIZE);

        uint16_t new_ethertype = vlan_hdr->ethertype;

        unsigned char* vlan_header_start_ptr = buffer_->get_data_start_ptr() + EthernetHeader::SIZE;
        unsigned char* payload_after_vlan_start_ptr = vlan_header_start_ptr + VlanHeader::SIZE;
        size_t payload_size = buffer_->get_data_length() - (EthernetHeader::SIZE + VlanHeader::SIZE);

        memmove(vlan_header_start_ptr, payload_after_vlan_start_ptr, payload_size);

        eth->ethertype = new_ethertype;

        if (!buffer_->set_data_len(buffer_->get_data_length() - VlanHeader::SIZE)) {
            return false;
        }
        l2_header_size_ -= VlanHeader::SIZE;

        update_checksums();
        return true;
    }

    void update_checksums() {
        if (!buffer_) return;

        ethernet();
        size_t current_l2_header_size = l2_header_size_;

        IPv4Header* ip4_hdr = get_header<IPv4Header>(current_l2_header_size);
        IPv6Header* ip6_hdr = nullptr;
        uint8_t l3_protocol = 0;
        size_t l3_header_length = 0;
        size_t l4_offset = 0;

        if (ip4_hdr && ( (ip4_hdr->version_ihl & 0xF0) >> 4 ) == 4) {
            l3_protocol = ip4_hdr->protocol;
            l3_header_length = ip4_hdr->get_header_length();
            l4_offset = current_l2_header_size + l3_header_length;

            ip4_hdr->header_checksum = 0;
            ip4_hdr->header_checksum = calculate_checksum(reinterpret_cast<const uint8_t*>(ip4_hdr), l3_header_length);
        } else {
            auto* eth_check = get_header<EthernetHeader>(0);
            uint16_t current_ethertype = eth_check ? ntohs(eth_check->ethertype) : 0;
            if (current_ethertype == ETHERTYPE_VLAN) {
                 auto* vlan_check = get_header<VlanHeader>(EthernetHeader::SIZE);
                 current_ethertype = vlan_check ? ntohs(vlan_check->ethertype) : 0;
            }

            if (current_ethertype == ETHERTYPE_IPV6) {
                ip4_hdr = nullptr;
                ip6_hdr = get_header<IPv6Header>(current_l2_header_size);
                if (ip6_hdr && ( (ntohl(ip6_hdr->version_tc_flowlabel) & 0xF0000000) >> 28 ) == 6) {
                    l3_protocol = ip6_hdr->next_header;
                    l3_header_length = IPv6Header::SIZE;
                    l4_offset = current_l2_header_size + l3_header_length;
                } else {
                    ip6_hdr = nullptr;
                    return;
                }
            } else {
                 ip4_hdr = nullptr;
                 ip6_hdr = nullptr;
                 return;
            }
        }

        TcpHeader* tcp_hdr = nullptr;
        UdpHeader* udp_hdr = nullptr;
        IcmpHeader* icmp_hdr = nullptr;
        const uint8_t* l4_payload_ptr = nullptr;
        size_t l4_payload_len = 0;

        if (l3_protocol == IPPROTO_TCP) {
            tcp_hdr = get_header<TcpHeader>(l4_offset);
            if (tcp_hdr) {
                size_t tcp_header_len = tcp_hdr->get_header_length();
                uint16_t tcp_segment_total_len;

                if (ip4_hdr) {
                    if (ntohs(ip4_hdr->total_length) < l3_header_length) return;
                    tcp_segment_total_len = ntohs(ip4_hdr->total_length) - l3_header_length;
                } else if (ip6_hdr) {
                    tcp_segment_total_len = ntohs(ip6_hdr->payload_length);
                } else { return; }

                if (tcp_segment_total_len < tcp_header_len) return;

                l4_payload_len = tcp_segment_total_len - tcp_header_len;
                l4_payload_ptr = buffer_->get_data_start_ptr() + l4_offset + tcp_header_len;

                if ((l4_offset + tcp_header_len + l4_payload_len) > buffer_->get_data_length()) {
                    return;
                }

                tcp_hdr->checksum = 0;

                std::vector<uint8_t> pseudo_header_plus_tcp;
                pseudo_header_plus_tcp.reserve(40 + tcp_segment_total_len);

                if (ip4_hdr) {
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<const uint8_t*>(&ip4_hdr->src_ip), reinterpret_cast<const uint8_t*>(&ip4_hdr->src_ip) + 4);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<const uint8_t*>(&ip4_hdr->dst_ip), reinterpret_cast<const uint8_t*>(&ip4_hdr->dst_ip) + 4);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(ip4_hdr->protocol);
                    uint16_t tcp_len_be = htons(tcp_segment_total_len);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<const uint8_t*>(&tcp_len_be), reinterpret_cast<const uint8_t*>(&tcp_len_be) + 2);
                } else if (ip6_hdr) {
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), &ip6_hdr->src_ip[0], &ip6_hdr->src_ip[0] + 16);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), &ip6_hdr->dst_ip[0], &ip6_hdr->dst_ip[0] + 16);
                    uint32_t tcp_len_be32 = htonl(tcp_segment_total_len);
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<uint8_t*>(&tcp_len_be32), reinterpret_cast<uint8_t*>(&tcp_len_be32) + 4);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(ip6_hdr->next_header);
                }

                pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<const uint8_t*>(tcp_hdr), reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_header_len);
                if (l4_payload_len > 0 && l4_payload_ptr) {
                     pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), l4_payload_ptr, l4_payload_ptr + l4_payload_len);
                }
                tcp_hdr->checksum = calculate_checksum(pseudo_header_plus_tcp.data(), pseudo_header_plus_tcp.size());
            }
        } else if (l3_protocol == IPPROTO_UDP) {
            udp_hdr = get_header<UdpHeader>(l4_offset);
            if (udp_hdr) {
                size_t udp_header_len = UdpHeader::SIZE;
                uint16_t udp_total_len_from_header = ntohs(udp_hdr->length);

                if (udp_total_len_from_header < udp_header_len) return;
                l4_payload_len = udp_total_len_from_header - udp_header_len;
                l4_payload_ptr = buffer_->get_data_start_ptr() + l4_offset + udp_header_len;

                if ((l4_offset + udp_header_len + l4_payload_len) > buffer_->get_data_length()) {
                    return;
                }

                udp_hdr->checksum = 0;

                std::vector<uint8_t> pseudo_header_plus_udp;
                pseudo_header_plus_udp.reserve(40 + udp_total_len_from_header);

                if (ip4_hdr) {
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(&ip4_hdr->src_ip), reinterpret_cast<const uint8_t*>(&ip4_hdr->src_ip) + 4);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(&ip4_hdr->dst_ip), reinterpret_cast<const uint8_t*>(&ip4_hdr->dst_ip) + 4);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(ip4_hdr->protocol);
                    uint16_t udp_len_be = htons(udp_total_len_from_header);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(&udp_len_be), reinterpret_cast<const uint8_t*>(&udp_len_be) + 2);
                } else if (ip6_hdr) {
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), &ip6_hdr->src_ip[0], &ip6_hdr->src_ip[0] + 16);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), &ip6_hdr->dst_ip[0], &ip6_hdr->dst_ip[0] + 16);
                    uint32_t udp_len_be32 = htonl(udp_total_len_from_header);
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<uint8_t*>(&udp_len_be32), reinterpret_cast<uint8_t*>(&udp_len_be32) + 4);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(ip6_hdr->next_header);
                }

                pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(udp_hdr), reinterpret_cast<const uint8_t*>(udp_hdr) + udp_header_len);
                if (l4_payload_len > 0 && l4_payload_ptr) {
                     pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), l4_payload_ptr, l4_payload_ptr + l4_payload_len);
                }

                uint16_t calculated_udp_checksum = calculate_checksum(pseudo_header_plus_udp.data(), pseudo_header_plus_udp.size());
                 if (calculated_udp_checksum == 0) { // Corrected placement
                    udp_hdr->checksum = 0xFFFF;
                } else {
                    udp_hdr->checksum = calculated_udp_checksum;
                }
            }
        } else if (l3_protocol == IPPROTO_ICMP) {
            if (ip4_hdr) {
                icmp_hdr = get_header<IcmpHeader>(l4_offset);
                if (icmp_hdr) {
                    if (ntohs(ip4_hdr->total_length) < l3_header_length) return;
                    size_t icmp_message_len = ntohs(ip4_hdr->total_length) - l3_header_length;

                    if ((l4_offset + icmp_message_len) > buffer_->get_data_length()) {
                        return;
                    }
                    if (icmp_message_len < IcmpHeader::MIN_SIZE) return;

                    icmp_hdr->checksum = 0;
                    icmp_hdr->checksum = calculate_checksum(reinterpret_cast<const uint8_t*>(icmp_hdr), icmp_message_len);
                }
            }
        }
    }

private:
    // Generic checksum calculation (RFC 1071)
    static uint16_t calculate_checksum(const uint8_t* data, size_t len) {
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

        while (len > 1) {
            sum += ntohs(*ptr++);
            len -= 2;
        }

        if (len > 0) {
            sum += ntohs(static_cast<uint16_t>(*reinterpret_cast<const uint8_t*>(ptr)) << 8);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return htons(static_cast<uint16_t>(~sum));
    }

    PacketBuffer* buffer_;
    mutable size_t current_offset_;
    mutable size_t l2_header_size_;

};

} // namespace netflow

#endif // NETFLOW_PACKET_HPP
