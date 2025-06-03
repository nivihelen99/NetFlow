#ifndef NETFLOW_PACKET_HPP
#define NETFLOW_PACKET_HPP

#include "packet_buffer.hpp" // Assumed to be self-contained or handled separately
#include <cstdint>   // For uint8_t, uint16_t, uint32_t
#include <vector>    // For std::vector
#include <optional>  // For std::optional, std::nullopt
#include <string>    // For std::string
#include <array>     // For std::array
#include <algorithm> // For std::copy, std::fill
#include <cstring>   // For memcpy, memmove, size_t (though <cstddef> is more direct for size_t)
#include <cstdio>    // For std::sscanf, std::snprintf
#include <stdexcept> // For std::invalid_argument
#include <cstddef>   // For std::size_t (though often included by others)

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
inline uint16_t htons_fallback(uint16_t val) {
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
    }
    return val;
}
inline uint16_t ntohs_fallback(uint16_t val) {
    uint16_t i = 1;
    bool is_little_endian = (*(char *)&i == 1);
    if (is_little_endian) {
        return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
    }
    return val;
}
inline uint32_t htonl_fallback(uint32_t val) {
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
inline uint32_t ntohl_fallback(uint32_t val) {
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
// Use macros to avoid name collision if system headers are found later by compiler but not preprocessor
#ifndef ntohs
#define ntohs ntohs_fallback
#endif
#ifndef htons
#define htons htons_fallback
#endif
#ifndef ntohl
#define ntohl ntohl_fallback
#endif
#ifndef htonl
#define htonl htonl_fallback
#endif

#endif


namespace netflow {

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct MacAddress {
    std::array<uint8_t, 6> bytes{};

    MacAddress() = default;

    MacAddress(const uint8_t* mac_bytes_ptr) {
        if (mac_bytes_ptr) {
            std::copy(mac_bytes_ptr, mac_bytes_ptr + 6, bytes.begin());
        } else {
            bytes.fill(0);
        }
    }

    MacAddress(const std::string& mac_str) {
        bytes.fill(0);
        if (mac_str.length() == 17) {
            unsigned int temp_b[6];
            int matched = std::sscanf(mac_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                                      &temp_b[0], &temp_b[1], &temp_b[2],
                                      &temp_b[3], &temp_b[4], &temp_b[5]);
            if (matched == 6) {
                for (std::size_t i = 0; i < 6; ++i) {
                    if (temp_b[i] > 255) {
                        bytes.fill(0);
                        return;
                    }
                    bytes[i] = static_cast<uint8_t>(temp_b[i]);
                }
            }
        }
    }

    bool operator==(const MacAddress& other) const {
        return bytes == other.bytes;
    }

    std::string to_string() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return std::string(buf);
    }

    bool is_zero() const {
        for(uint8_t b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }

    bool is_broadcast() const {
        for(uint8_t b : bytes) {
            if (b != 0xFF) return false;
        }
        return true;
    }

    bool operator<(const MacAddress& other) const {
        return bytes < other.bytes;
    }
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

constexpr uint8_t IPPROTO_ICMP = 1;
constexpr uint8_t IPPROTO_TCP = 6;
constexpr uint8_t IPPROTO_UDP = 17;

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct EthernetHeader {
    MacAddress dst_mac;
    MacAddress src_mac;
    uint16_t ethertype;
    static constexpr std::size_t SIZE = sizeof(MacAddress) * 2 + sizeof(uint16_t);
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct VlanHeader {
    uint16_t tci;
    uint16_t ethertype;
    static constexpr std::size_t SIZE = sizeof(uint16_t) * 2;

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
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct LLCHeader {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
    static constexpr std::size_t SIZE = 3;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct IPv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    static constexpr std::size_t MIN_SIZE = 20;
    std::size_t get_header_length() const { return (version_ihl & 0x0F) * 4; }
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct IPv6Header {
    uint32_t version_tc_flowlabel;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    static constexpr std::size_t SIZE = 40;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    static constexpr std::size_t MIN_SIZE = 20;
    std::size_t get_header_length() const { return ((data_offset_reserved_flags & 0xF0) >> 4) * 4; }
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    static constexpr std::size_t SIZE = 8;
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

using IpAddress = uint32_t;

uint8_t ip_mask_to_prefix_length(IpAddress subnet_mask);

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct ArpHeader {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_addr_len;
    uint8_t  protocol_addr_len;
    uint16_t opcode;
    MacAddress sender_mac;
    IpAddress  sender_ip;
    MacAddress target_mac;
    IpAddress  target_ip;
    static constexpr std::size_t SIZE = 2 * sizeof(uint16_t) + 2 * sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(MacAddress) + 2 * sizeof(IpAddress);
};
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
    static constexpr uint8_t TYPE_ECHO_REPLY = 0;
    static constexpr uint8_t TYPE_ECHO_REQUEST = 8;
    static constexpr std::size_t MIN_SIZE = sizeof(uint8_t) * 2 + sizeof(uint16_t) * 3;
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

    Packet(const Packet&) = delete;
    Packet& operator=(const Packet&) = delete;

    Packet(Packet&& other) noexcept : buffer_(other.buffer_), current_offset_(other.current_offset_), l2_header_size_(other.l2_header_size_) {
        other.buffer_ = nullptr;
    }

    Packet& operator=(Packet&& other) noexcept {
        if (this != &other) {
            if (buffer_) {
                buffer_->decrement_ref();
            }
            buffer_ = other.buffer_;
            current_offset_ = other.current_offset_;
            l2_header_size_ = other.l2_header_size_;
            other.buffer_ = nullptr;
        }
        return *this;
    }

    PacketBuffer* get_buffer() const { return buffer_; }

    template <typename HeaderType>
    HeaderType* get_header(std::size_t offset) const {
        if (!buffer_ || offset + sizeof(HeaderType) > buffer_->get_data_length()) {
            return nullptr;
        }
        return reinterpret_cast<HeaderType*>(buffer_->get_data_start_ptr() + offset);
    }

    template <typename HeaderType>
    HeaderType* get_header_at_current_offset() const {
        if (!buffer_ || current_offset_ + sizeof(HeaderType) > buffer_->get_data_length()) {
            return nullptr;
        }
        HeaderType* header = reinterpret_cast<HeaderType*>(buffer_->get_data_start_ptr() + current_offset_);
        return header;
    }

    EthernetHeader* ethernet() const {
        current_offset_ = 0;
        auto* eth = get_header<EthernetHeader>(current_offset_);
        if (eth) {
            if (ntohs(eth->ethertype) == ETHERTYPE_VLAN) {
                l2_header_size_ = EthernetHeader::SIZE + VlanHeader::SIZE;
            } else {
                l2_header_size_ = EthernetHeader::SIZE;
            }
        }
        return eth;
    }

    VlanHeader* vlan() const {
        auto* eth = get_header<EthernetHeader>(0);
        if (eth && ntohs(eth->ethertype) == ETHERTYPE_VLAN) {
            return get_header<VlanHeader>(EthernetHeader::SIZE);
        }
        return nullptr;
    }

    IPv4Header* ipv4() const {
        current_offset_ = l2_header_size_;
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
             if (ip_head) current_offset_ += ip_head->get_header_length();
             return ip_head;
        }
        return nullptr;
    }

    IPv6Header* ipv6() const {
        current_offset_ = l2_header_size_;
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
            if (ip6_head) current_offset_ += IPv6Header::SIZE;
            return ip6_head;
        }
        return nullptr;
    }

    TcpHeader* tcp() const {
        ethernet(); 

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr;

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr;
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) {
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_TCP) {
                std::size_t l4_offset = l2_header_size_ + ip4->get_header_length();
                return get_header<TcpHeader>(l4_offset);
            }
        } else if (effective_ethertype == ETHERTYPE_IPV6) {
            IPv6Header* ip6 = get_header<IPv6Header>(l2_header_size_);
            if (ip6 && ip6->next_header == IPPROTO_TCP) {
                std::size_t l4_offset = l2_header_size_ + IPv6Header::SIZE;
                return get_header<TcpHeader>(l4_offset);
            }
        }
        return nullptr;
    }

    UdpHeader* udp() const {
        ethernet();

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr;

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr;
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) {
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_UDP) {
                std::size_t l4_offset = l2_header_size_ + ip4->get_header_length();
                return get_header<UdpHeader>(l4_offset);
            }
        } else if (effective_ethertype == ETHERTYPE_IPV6) {
            IPv6Header* ip6 = get_header<IPv6Header>(l2_header_size_);
            if (ip6 && ip6->next_header == IPPROTO_UDP) {
                std::size_t l4_offset = l2_header_size_ + IPv6Header::SIZE;
                return get_header<UdpHeader>(l4_offset);
            }
        }
        return nullptr;
    }

    ArpHeader* arp() const {
        ethernet();
        current_offset_ = l2_header_size_;
        auto* eth = get_header<EthernetHeader>(0);
        if (!eth) return nullptr;

        uint16_t effective_ethertype = ntohs(eth->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            auto* vlan_hdr = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr) return nullptr;
            effective_ethertype = ntohs(vlan_hdr->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_ARP) {
            return get_header<ArpHeader>(current_offset_);
        }
        return nullptr;
    }

    IcmpHeader* icmp() const {
        ethernet();

        uint16_t effective_ethertype = 0;
        auto* eth_hdr_check = get_header<EthernetHeader>(0);
        if (!eth_hdr_check) return nullptr;

        effective_ethertype = ntohs(eth_hdr_check->ethertype);
        if (effective_ethertype == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr_check = get_header<VlanHeader>(EthernetHeader::SIZE);
            if (!vlan_hdr_check) return nullptr;
            effective_ethertype = ntohs(vlan_hdr_check->ethertype);
        }

        if (effective_ethertype == ETHERTYPE_IPV4) {
            IPv4Header* ip4 = get_header<IPv4Header>(l2_header_size_);
            if (ip4 && ip4->protocol == IPPROTO_ICMP) {
                std::size_t icmp_offset = l2_header_size_ + ip4->get_header_length();
                return get_header<IcmpHeader>(icmp_offset);
            }
        }
        return nullptr;
    }

    bool has_vlan() const {
        auto* eth = ethernet();
        return eth && ntohs(eth->ethertype) == ETHERTYPE_VLAN;
    }

    std::optional<uint16_t> vlan_id() const {
        if (has_vlan()) {
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
            std::size_t l3_len = buffer_->get_data_length() - EthernetHeader::SIZE;

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
        std::size_t payload_size = buffer_->get_data_length() - (EthernetHeader::SIZE + VlanHeader::SIZE);

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
        std::size_t current_l2_header_size = l2_header_size_;

        IPv4Header* ip4_hdr = get_header<IPv4Header>(current_l2_header_size);
        IPv6Header* ip6_hdr = nullptr;
        uint8_t l3_protocol = 0;
        std::size_t l3_header_length = 0;
        std::size_t l4_offset = 0;

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
                ip4_hdr = nullptr; // Not IPv4
                ip6_hdr = get_header<IPv6Header>(current_l2_header_size);
                if (ip6_hdr && ( (ntohl(ip6_hdr->version_tc_flowlabel) & 0xF0000000) >> 28 ) == 6) {
                    l3_protocol = ip6_hdr->next_header;
                    l3_header_length = IPv6Header::SIZE;
                    l4_offset = current_l2_header_size + l3_header_length;
                } else {
                    ip6_hdr = nullptr; // Not a valid IPv6 header
                    return; // Cannot proceed with L4 checksums
                }
            } else {
                 ip4_hdr = nullptr; // Not IPv4
                 ip6_hdr = nullptr; // Not IPv6 either
                 return; // No known L3 to process for L4 checksums
            }
        }

        TcpHeader* tcp_hdr = nullptr;
        UdpHeader* udp_hdr = nullptr;
        IcmpHeader* icmp_hdr = nullptr; // For ICMPv4
        const uint8_t* l4_payload_ptr = nullptr;
        std::size_t l4_payload_len = 0;

        if (l3_protocol == IPPROTO_TCP) {
            tcp_hdr = get_header<TcpHeader>(l4_offset);
            if (tcp_hdr) {
                std::size_t tcp_header_len = tcp_hdr->get_header_length();
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
                pseudo_header_plus_tcp.reserve(40 + tcp_segment_total_len); // Max IPv6 pseudo + TCP segment

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
                    uint32_t tcp_len_be32 = htonl(tcp_segment_total_len); // Length is 32-bit for IPv6 pseudo header
                    pseudo_header_plus_tcp.insert(pseudo_header_plus_tcp.end(), reinterpret_cast<const uint8_t*>(&tcp_len_be32), reinterpret_cast<const uint8_t*>(&tcp_len_be32) + 4);
                    pseudo_header_plus_tcp.push_back(0); // 3 bytes of zero padding
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(0);
                    pseudo_header_plus_tcp.push_back(ip6_hdr->next_header); // Protocol
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
                std::size_t udp_header_len = UdpHeader::SIZE;
                uint16_t udp_total_len_from_header = ntohs(udp_hdr->length);

                if (udp_total_len_from_header < udp_header_len) return;
                l4_payload_len = udp_total_len_from_header - udp_header_len;
                l4_payload_ptr = buffer_->get_data_start_ptr() + l4_offset + udp_header_len;

                if ((l4_offset + udp_header_len + l4_payload_len) > buffer_->get_data_length()) {
                    return;
                }
                
                udp_hdr->checksum = 0; // UDP checksum can be 0 if not used (for IPv4). If calculated as 0, it's sent as 0xFFFF.

                std::vector<uint8_t> pseudo_header_plus_udp;
                pseudo_header_plus_udp.reserve(40 + udp_total_len_from_header); // Max IPv6 pseudo + UDP segment

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
                    uint32_t udp_len_be32 = htonl(udp_total_len_from_header); // Length is 32-bit for IPv6 pseudo header
                    pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(&udp_len_be32), reinterpret_cast<const uint8_t*>(&udp_len_be32) + 4);
                    pseudo_header_plus_udp.push_back(0); // 3 bytes of zero padding
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(0);
                    pseudo_header_plus_udp.push_back(ip6_hdr->next_header); // Protocol
                }

                pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), reinterpret_cast<const uint8_t*>(udp_hdr), reinterpret_cast<const uint8_t*>(udp_hdr) + udp_header_len);
                if (l4_payload_len > 0 && l4_payload_ptr) {
                     pseudo_header_plus_udp.insert(pseudo_header_plus_udp.end(), l4_payload_ptr, l4_payload_ptr + l4_payload_len);
                }
                
                // For UDP over IPv4, checksum is optional. If 0, it means it wasn't calculated.
                // For UDP over IPv6, checksum is mandatory.
                // If the calculated checksum is 0, it is transmitted as 0xFFFF.
                if (ip6_hdr || (ip4_hdr && udp_total_len_from_header > 0) ) { // Calculate checksum for IPv6 or if data exists for IPv4
                    uint16_t calculated_udp_checksum = calculate_checksum(pseudo_header_plus_udp.data(), pseudo_header_plus_udp.size());
                    if (calculated_udp_checksum == 0) {
                        udp_hdr->checksum = 0xFFFF;
                    } else {
                        udp_hdr->checksum = calculated_udp_checksum;
                    }
                } else {
                    udp_hdr->checksum = 0; // Optional for IPv4 and no data
                }
            }
        } else if (l3_protocol == IPPROTO_ICMP) { // ICMPv4
            if (ip4_hdr) { // ICMPv4 is only with IPv4
                icmp_hdr = get_header<IcmpHeader>(l4_offset);
                if (icmp_hdr) {
                    if (ntohs(ip4_hdr->total_length) < l3_header_length) return;
                    std::size_t icmp_message_len = ntohs(ip4_hdr->total_length) - l3_header_length;

                    if ((l4_offset + icmp_message_len) > buffer_->get_data_length()) {
                        return;
                    }
                    if (icmp_message_len < IcmpHeader::MIN_SIZE) return; // Ensure at least base ICMP header

                    icmp_hdr->checksum = 0;
                    icmp_hdr->checksum = calculate_checksum(reinterpret_cast<const uint8_t*>(icmp_hdr), icmp_message_len);
                }
            }
            // ICMPv6 would be protocol 58 and need its own handling for pseudo-header.
        }
    }

private:
    static uint16_t calculate_checksum(const uint8_t* data, std::size_t len) {
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

        while (len > 1) {
            sum += ntohs(*ptr++); // Network to host for summation, then host to network for storage
            len -= 2;
        }

        if (len > 0) { // Odd byte
            sum += ntohs(static_cast<uint16_t>(*reinterpret_cast<const uint8_t*>(ptr)) << 8);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return htons(static_cast<uint16_t>(~sum));
    }

    PacketBuffer* buffer_;
    mutable std::size_t current_offset_;
    mutable std::size_t l2_header_size_;
};

} // namespace netflow

#endif // NETFLOW_PACKET_HPP
