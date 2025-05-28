#ifndef NETFLOW_PACKET_PACKET_H
#define NETFLOW_PACKET_PACKET_H

#include "netflow/core/PacketBuffer.h"
#include "netflow/packet/ethernet.h" // For netflow::packet::EthernetHeader and ethertypes
#include "netflow/packet/ip.h"       // For netflow::packet::IpHeader and IP protocol numbers
#include <cstdint>
#include <array>
#include <vector> // For methods that might return data as vector
#include <arpa/inet.h> // For ntohs, htons (used in VlanTag helpers)

// Define VlanTag, TCPHeader, UDPHeader within netflow::packet namespace
namespace netflow {
namespace packet {

// EthernetHeader and IpHeader are now included from their respective files
// ETHERTYPE_IP, ETHERTYPE_ARP, IPPROTO_ICMP etc are also from those files.

// Simplified TCP Header structure
struct TcpHeader {
    uint16_t src_port; // Network byte order
    uint16_t dst_port; // Network byte order
    uint32_t seq_number; // Network byte order
    uint32_t ack_number; // Network byte order
    uint8_t  data_offset_reserved_flags; // Data Offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
    uint8_t  flags; // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint16_t window_size; // Network byte order
    uint16_t checksum;    // Network byte order
    uint16_t urgent_pointer; // Network byte order
    // Options would follow

    // Helper to get data offset in bytes
    uint8_t get_data_offset_bytes() const { return (data_offset_reserved_flags >> 4) * 4; }
} __attribute__((packed));

// Simplified UDP Header structure
struct UdpHeader {
    uint16_t src_port; // Network byte order
    uint16_t dst_port; // Network byte order
    uint16_t length;   // Length of UDP header and data, network byte order
    uint16_t checksum; // Network byte order
} __attribute__((packed));

// VlanTag structure (802.1Q)
struct VlanTag {
    uint16_t tci;      // Tag Control Information (PCP:3, DEI:1, VID:12), network byte order
    uint16_t ethertype; // Ethertype of the encapsulated frame, network byte order

    uint16_t get_vlan_id() const { return ntohs(tci) & 0x0FFF; }
    uint8_t get_priority_code_point() const { return (ntohs(tci) >> 13) & 0x07; }
    bool get_dei() const { return (ntohs(tci) >> 12) & 0x01; }
} __attribute__((packed));

// Common TPID for VLAN
constexpr uint16_t VLAN_TPID = 0x8100;

} // namespace packet
} // namespace netflow


class Packet {
public:
    // Constructor: Takes ownership of a PacketBuffer
    explicit Packet(PacketBuffer* buf);
    // Constructor: From raw data (copies data into a new internal PacketBuffer)
    Packet(const void* data, size_t len, size_t buffer_size_to_alloc = 2048);

    // Destructor
    ~Packet();

    // Access the underlying PacketBuffer
    PacketBuffer* get_buffer() const;

    // Get pointer to the start of the packet data within the buffer
    unsigned char* head() const;
    // Get current packet length
    size_t length() const;
    // Set packet length (e.g., after encapsulation/decapsulation)
    void set_length(size_t len);

    // Generic header access (use with caution, prefer specific accessors)
    template <typename HeaderType>
    HeaderType* get_header(size_t offset = 0) const {
        if (!head_data_ptr_ || offset + sizeof(HeaderType) > current_length_) {
            return nullptr; 
        }
        return reinterpret_cast<HeaderType*>(head_data_ptr_ + offset);
    }

    // Specific header accessors
    netflow::packet::EthernetHeader* ethernet() const;
    netflow::packet::VlanTag* vlan_tag_header() const; // Returns pointer to VLAN tag if present
    netflow::packet::IpHeader* ipv4() const;
    // netflow::packet::ArpHeader* arp() const; // Would require including arp.h
    netflow::packet::TcpHeader* tcp() const;
    netflow::packet::UdpHeader* udp() const;
    // netflow::protocols::icmp::IcmpHeader* icmp() const; // Would require including icmp.h

    // L2 information
    bool has_vlan() const;
    uint16_t vlan_id() const; // Returns 0 if no VLAN
    uint8_t vlan_priority() const; // Returns 0 if no VLAN
    std::array<uint8_t, 6> src_mac() const;
    std::array<uint8_t, 6> dst_mac() const;
    uint16_t get_actual_ethertype() const; // Ethertype after VLAN tag (if any)

    // L3 information (IPv4 specific for now)
    uint32_t get_src_ip() const; // Returns 0 if not IPv4
    uint32_t get_dst_ip() const; // Returns 0 if not IPv4
    uint8_t get_ip_protocol() const; // Returns 0 if not IPv4

    // L4 information
    uint16_t get_src_port() const; // Returns 0 if not TCP/UDP or no L4 info
    uint16_t get_dst_port() const; // Returns 0 if not TCP/UDP or no L4 info


    // Packet manipulation methods
    bool set_dst_mac(const std::array<uint8_t, 6>& new_dst_mac);
    bool set_src_mac(const std::array<uint8_t, 6>& new_src_mac);
    
    // push_vlan and pop_vlan are complex: they modify packet structure and length.
    // These require careful buffer management (checking space, moving data).
    bool push_vlan(uint16_t tci_val_host_order); // TPID is standard 0x8100
    bool pop_vlan();
    
    void update_checksums(); // Placeholder for general checksum recalculation
    void update_ip_checksum(); // Specifically for IPv4 header checksum

private:
    PacketBuffer* buffer_;      // Packet holds a reference to a PacketBuffer
    unsigned char* head_data_ptr_; // Pointer to the start of packet data within the buffer_
    size_t current_length_;   // Current length of the packet data
    bool owns_buffer_; 

    // Parsed offsets and information
    // intptr_t l2_offset_ = 0; // Ethernet header is assumed at offset 0 from head_data_ptr_
    intptr_t l3_offset_ = -1; // Offset to L3 header (IP or ARP) from start of head_data_ptr_
    intptr_t l4_offset_ = -1; // Offset to L4 header (TCP, UDP, ICMP) from start of head_data_ptr_
    uint16_t actual_ethertype_ = 0; // Ethertype after potentially stripping VLAN tag(s), host byte order
    bool has_vlan_tag_ = false;

    void parse_packet(); // Internal method to parse headers and set offsets
};

#endif // NETFLOW_PACKET_PACKET_H
