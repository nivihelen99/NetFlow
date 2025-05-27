#ifndef NETFLOW_PACKET_PACKET_H
#define NETFLOW_PACKET_PACKET_H

#include "netflow/core/PacketBuffer.h"
#include <cstdint> // For fixed-width integers
#include <type_traits> // For std::is_base_of, std::enable_if
#include <array> // For std::array (MACAddress)

// Placeholder for protocol header structures (to be defined in netflow/protocols/)
// For now, we can define simplified versions here or just forward declare.
namespace netflow {
namespace protocols {

// Simplified Ethernet Header structure
struct EthernetHeader {
    std::array<uint8_t, 6> dst_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ethertype;
    // Not including CRC/FCS here as it's often handled by hardware
};

// Simplified VLAN Tag structure (802.1Q)
struct VlanTag {
    uint16_t tci; // Tag Control Information (PCP:3, DEI:1, VID:12)
    uint16_t ethertype; // Ethertype of the encapsulated frame
};

// Simplified IPv4 Header structure
struct IPv4Header {
    uint8_t version_ihl; // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t dscp_ecn;    // Differentiated Services Code Point (6 bits) + Explicit Congestion Notification (2 bits)
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    // Options would follow if IHL > 5
};

// Simplified TCP Header structure
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved_flags; // Data Offset (4 bits) + Reserved (3 bits) + Flags (NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN - 9 bits total, but usually split)
    uint8_t flags; // Just the flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    // Options would follow
};

// Simplified UDP Header structure
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// Add IPv6Header later if needed

} // namespace protocols
} // namespace netflow


class Packet {
public:
    // Constructor: Takes ownership of a PacketBuffer
    explicit Packet(PacketBuffer* buf);
    // Constructor: From raw data (copies data into a new internal PacketBuffer)
    // This might be used for testing or creating packets from scratch.
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

    // Template-based header access
    template <typename HeaderType>
    HeaderType* get_header(size_t offset = 0) const {
        // Basic check, could be more robust (e.g. checking if offset + sizeof(HeaderType) <= length())
        if (offset + sizeof(HeaderType) > length()) {
            return nullptr; 
        }
        return reinterpret_cast<HeaderType*>(head() + offset);
    }

    // Direct accessors for common headers (assuming fixed offsets for simplicity here)
    // A more robust implementation would parse and store offsets.
    netflow::protocols::EthernetHeader* ethernet(size_t offset = 0) const;
    netflow::protocols::VlanTag* vlan(size_t offset = 12) const; // Offset after MACs, before ethertype if no VLAN
    netflow::protocols::IPv4Header* ipv4(size_t offset = 14) const; // Default offset after Ethernet
    // netflow::protocols::IPv6Header* ipv6(size_t offset = 14) const; // Placeholder
    netflow::protocols::TCPHeader* tcp(size_t offset = 34) const;   // Default offset after Eth+IPv4 (20B)
    netflow::protocols::UDPHeader* udp(size_t offset = 34) const;   // Default offset after Eth+IPv4 (20B)

    // Layer 2 specific methods
    bool has_vlan() const; // This would require parsing to be accurate
    uint16_t vlan_id() const;
    uint8_t vlan_priority() const;
    std::array<uint8_t, 6> src_mac() const;
    std::array<uint8_t, 6> dst_mac() const;

    // Packet manipulation methods
    bool set_dst_mac(const std::array<uint8_t, 6>& new_dst_mac);
    // push_vlan and pop_vlan are complex as they modify packet structure and length
    // These would require careful buffer management (checking space, moving data)
    bool push_vlan(uint16_t tpid, uint16_t tci); // TPID (e.g. 0x8100), TCI (PCP, DEI, VID)
    bool pop_vlan();
    void update_checksums(); // Placeholder for checksum recalculation

    // Methods to adjust packet data pointers (e.g., after adding/removing headers)
    // void* push(size_t len); // Add data to the beginning, returns pointer to new start
    // void* pull(size_t len); // Remove data from the beginning, returns pointer to old start (now invalid)
    // void* put(size_t len);  // Add data to the end, returns pointer to where new data was added
    // void* trim(size_t len); // Remove data from the end

private:
    PacketBuffer* buffer_;      // Packet holds a reference to a PacketBuffer
    unsigned char* head_data_ptr_; // Pointer to the start of packet data within the buffer_
    size_t current_length_;   // Current length of the packet data

    // Helper to manage buffer ownership. If true, this Packet object created and owns the buffer.
    bool owns_buffer_; 

    // Internal offsets for known headers (would be populated during parsing)
    // For simplicity, we are using fixed offsets in direct accessors for now.
    // intptr_t l2_offset_ = 0;
    // intptr_t l3_offset_ = -1;
    // intptr_t l4_offset_ = -1;
    // void parse_packet(); // A method to parse and identify header offsets
};

#endif // NETFLOW_PACKET_PACKET_H
