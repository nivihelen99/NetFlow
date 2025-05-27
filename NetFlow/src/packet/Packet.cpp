#include "netflow/packet/Packet.h"
#include <cstring> // For memcpy
#include <stdexcept> // For std::runtime_error
#include <iostream>  // For debug/error messages
#include <arpa/inet.h> // For ntohs, htons (if doing checksums or multi-byte fields)

// --- Packet Implementation ---

Packet::Packet(PacketBuffer* buf)
    : buffer_(buf), owns_buffer_(false) {
    if (!buffer_) {
        throw std::runtime_error("PacketBuffer cannot be null for Packet construction.");
    }
    // This packet uses the provided buffer. Increment its ref count.
    buffer_->ref(); 
    head_data_ptr_ = static_cast<unsigned char*>(buffer_->data());
    current_length_ = buffer_->data_len(); 
    // In a real scenario, head_data_ptr_ might be offset if buffer has headroom.
    // And current_length would be the actual packet data length, not necessarily buffer's full data_len.
}

Packet::Packet(const void* data, size_t len, size_t buffer_size_to_alloc)
    : buffer_(nullptr), owns_buffer_(true) {
    if (!data || len == 0) {
        throw std::runtime_error("Invalid data or length for Packet construction from raw data.");
    }
    size_t alloc_size = (buffer_size_to_alloc < len) ? len : buffer_size_to_alloc;
    if (alloc_size < 64) alloc_size = 64; // Minimum typical buffer size

    // Create and manage its own PacketBuffer
    // The PacketBuffer created here is assumed to be single-use for this packet,
    // so its ref_count will be 1 (held by this Packet object implicitly).
    // If this PacketBuffer were to be shared, its ref() would need to be called.
    buffer_ = new PacketBuffer(alloc_size); // No NUMA node specified for this simple case
    // buffer_->ref(); // Not strictly needed if only this Packet uses it and deletes it.

    if (len > buffer_->size()) {
        delete buffer_; // Clean up allocated buffer
        throw std::runtime_error("Data length exceeds allocated buffer size in Packet constructor.");
    }
    
    std::memcpy(buffer_->data(), data, len);
    buffer_->set_data_len(len);

    head_data_ptr_ = static_cast<unsigned char*>(buffer_->data());
    current_length_ = len;
}


Packet::~Packet() {
    if (buffer_) {
        if (owns_buffer_) {
            delete buffer_; // This Packet created and owns the buffer
        } else {
            buffer_->unref(); // Release the reference to the shared buffer
        }
        buffer_ = nullptr;
    }
}

PacketBuffer* Packet::get_buffer() const {
    return buffer_;
}

unsigned char* Packet::head() const {
    // Assuming head_data_ptr_ is always pointing to the start of packet data
    // in the buffer_.
    return head_data_ptr_;
}

size_t Packet::length() const {
    return current_length_;
}

void Packet::set_length(size_t len) {
    if (buffer_ && len > buffer_->size()) {
        // Or handle error: throw std::length_error("New packet length exceeds buffer capacity.");
        // std::cerr << "Error: New packet length " << len << " exceeds buffer capacity " << buffer_->size() << std::endl;
        current_length_ = buffer_->size(); // Truncate to buffer capacity
        buffer_->set_data_len(current_length_);
    } else {
        current_length_ = len;
        if (buffer_) {
            buffer_->set_data_len(current_length_);
        }
    }
}


// Direct accessors - these are highly simplified and assume fixed offsets
// A proper implementation would parse the packet to find these offsets.
netflow::protocols::EthernetHeader* Packet::ethernet(size_t offset) const {
    return get_header<netflow::protocols::EthernetHeader>(offset);
}

netflow::protocols::VlanTag* Packet::vlan(size_t offset) const {
    // Basic check for ethertype indicating VLAN (0x8100)
    // This is still simplified as there could be QinQ.
    // A full parser would be needed.
    auto eth_hdr = ethernet();
    if (eth_hdr && ntohs(eth_hdr->ethertype) == 0x8100) {
         // The 'offset' parameter here is relative to packet start.
         // If ethertype is 0x8100, the VLAN tag starts right after src_mac/dst_mac/ethertype_field_for_vlan
         // So, offset should be where the TPID (0x8100) is found.
        return get_header<netflow::protocols::VlanTag>(offset);
    }
    return nullptr;
}

netflow::protocols::IPv4Header* Packet::ipv4(size_t offset) const {
    // This needs to check ethertype to be robust
    auto eth_hdr = ethernet();
    if (!eth_hdr) return nullptr;

    uint16_t ethertype = ntohs(eth_hdr->ethertype);
    size_t current_offset = sizeof(netflow::protocols::EthernetHeader);

    if (ethertype == 0x8100) { // VLAN
        // If default offset is used for vlan(), it assumes vlan tag is at offset 12.
        // We should use the current_offset to locate the VLAN tag.
        auto vlan_hdr = get_header<netflow::protocols::VlanTag>(current_offset);
        if (!vlan_hdr) return nullptr;
        ethertype = ntohs(vlan_hdr->ethertype);
        current_offset += sizeof(netflow::protocols::VlanTag);
    }

    if (ethertype == 0x0800) { // IPv4
        return get_header<netflow::protocols::IPv4Header>(current_offset);
    }
    return nullptr;
}

netflow::protocols::TCPHeader* Packet::tcp(size_t offset) const {
    auto ip_hdr = ipv4(); // This uses the smart ipv4() which finds its own offset
    if (ip_hdr && ip_hdr->protocol == 6) { // 6 for TCP
        // Calculate offset based on IPv4 header length (IHL)
        size_t ip_header_len = (ip_hdr->version_ihl & 0x0F) * 4;
        // Find IPv4 header start:
        unsigned char* ptr = reinterpret_cast<unsigned char*>(ip_hdr);
        size_t ipv4_start_offset = ptr - head();
        return get_header<netflow::protocols::TCPHeader>(ipv4_start_offset + ip_header_len);
    }
    return nullptr;
}

netflow::protocols::UDPHeader* Packet::udp(size_t offset) const {
    auto ip_hdr = ipv4(); // This uses the smart ipv4() which finds its own offset
    if (ip_hdr && ip_hdr->protocol == 17) { // 17 for UDP
        size_t ip_header_len = (ip_hdr->version_ihl & 0x0F) * 4;
        unsigned char* ptr = reinterpret_cast<unsigned char*>(ip_hdr);
        size_t ipv4_start_offset = ptr - head();
        return get_header<netflow::protocols::UDPHeader>(ipv4_start_offset + ip_header_len);
    }
    return nullptr;
}


// Layer 2 specific methods
bool Packet::has_vlan() const {
    auto eth_hdr = ethernet();
    if (eth_hdr) {
        return ntohs(eth_hdr->ethertype) == 0x8100;
    }
    return false;
}

uint16_t Packet::vlan_id() const {
    if (has_vlan()) {
        // Assumes VLAN tag is directly after Ethernet header if ethertype is 0x8100
        // The VlanTag itself starts *after* the TPID field, which is eth_hdr->ethertype
        auto vlan_hdr = get_header<netflow::protocols::VlanTag>(sizeof(netflow::protocols::EthernetHeader) - sizeof(uint16_t)); // Offset to start of TCI
        if (vlan_hdr) { // vlan_hdr now points to where TCI is.
            return ntohs(vlan_hdr->tci) & 0x0FFF; // Lower 12 bits for VID
        }
    }
    return 0; // Or some indicator of no VLAN ID
}

uint8_t Packet::vlan_priority() const {
    if (has_vlan()) {
        auto vlan_hdr = get_header<netflow::protocols::VlanTag>(sizeof(netflow::protocols::EthernetHeader) - sizeof(uint16_t)); // Offset to start of TCI
        if (vlan_hdr) {
            return (ntohs(vlan_hdr->tci) >> 13) & 0x07; // Upper 3 bits for PCP
        }
    }
    return 0; // Default priority
}

std::array<uint8_t, 6> Packet::src_mac() const {
    auto eth_hdr = ethernet();
    if (eth_hdr) {
        return eth_hdr->src_mac;
    }
    return {}; // Return empty or error
}

std::array<uint8_t, 6> Packet::dst_mac() const {
    auto eth_hdr = ethernet();
    if (eth_hdr) {
        return eth_hdr->dst_mac;
    }
    return {}; // Return empty or error
}

// Packet manipulation methods
bool Packet::set_dst_mac(const std::array<uint8_t, 6>& new_dst_mac) {
    auto eth_hdr = ethernet();
    if (eth_hdr) {
        eth_hdr->dst_mac = new_dst_mac;
        return true;
    }
    return false;
}

bool Packet::push_vlan(uint16_t tpid, uint16_t tci) {
    if (!buffer_ || !head_data_ptr_) return false;

    auto eth_hdr = ethernet();
    if (!eth_hdr) return false; 

    size_t vlan_tag_size = sizeof(netflow::protocols::VlanTag);
    if (current_length_ + vlan_tag_size > buffer_->size() - (head_data_ptr_ - static_cast<unsigned char*>(buffer_->data())) ) {
        // std::cerr << "Error: Not enough space in buffer to push VLAN tag." << std::endl;
        return false; 
    }

    unsigned char* ethertype_field_ptr = reinterpret_cast<unsigned char*>(&eth_hdr->ethertype);
    uint16_t original_ethertype_value = eth_hdr->ethertype; // Already in network byte order

    // Make space for VLAN tag (TCI + new Ethertype) by shifting data starting from original ethertype
    // The new VLAN tag (4 bytes) will replace the original ethertype (2 bytes) and add 2 more bytes.
    // So, we need to shift data by (vlan_tag_size - sizeof(uint16_t)) = 2 bytes.
    // Actually, we shift the payload that was *after* the original ethertype.
    // The VLAN TCI and VLAN Ethertype will be inserted. The original eth_hdr->ethertype field becomes the TPID.
    
    unsigned char* payload_start_ptr = ethertype_field_ptr + sizeof(uint16_t);
    size_t payload_len = current_length_ - (payload_start_ptr - head_data_ptr_);

    // Shift payload to make space for the TCI and the new Ethertype field of the VLAN tag
    std::memmove(payload_start_ptr + sizeof(netflow::protocols::VlanTag) - sizeof(uint16_t), 
                   payload_start_ptr, 
                   payload_len);

    // Set TPID
    eth_hdr->ethertype = htons(tpid);

    // Insert TCI and original Ethertype (which becomes the Ethertype field of the VLAN tag)
    netflow::protocols::VlanTag* new_vlan_tag_ptr = reinterpret_cast<netflow::protocols::VlanTag*>(ethertype_field_ptr + sizeof(uint16_t));
    new_vlan_tag_ptr->tci = htons(tci);
    new_vlan_tag_ptr->ethertype = original_ethertype_value; // original_ethertype_value is already network order

    current_length_ += (sizeof(netflow::protocols::VlanTag) - sizeof(uint16_t)); // Net addition of 2 bytes
    buffer_->set_data_len(current_length_);
    // update_checksums(); 
    return true;
}

bool Packet::pop_vlan() {
    if (!has_vlan()) return false;

    auto eth_hdr = ethernet();
    if (!eth_hdr) return false;

    // VLAN tag starts right after MACs. eth_hdr->ethertype is the TPID (e.g. 0x8100)
    // The VlanTag struct (TCI + encapsulated Ethertype) follows the TPID.
    unsigned char* tpid_ptr = reinterpret_cast<unsigned char*>(&eth_hdr->ethertype);
    netflow::protocols::VlanTag* vlan_tag_ptr = reinterpret_cast<netflow::protocols::VlanTag*>(tpid_ptr + sizeof(uint16_t));
    
    uint16_t encapsulated_ethertype = vlan_tag_ptr->ethertype; // Already network byte order

    // Data to move starts after the full VLAN tag (TPID + TCI + VlanEthertype)
    unsigned char* data_after_vlan_ptr = reinterpret_cast<unsigned char*>(vlan_tag_ptr) + sizeof(netflow::protocols::VlanTag) - sizeof(uint16_t); // Points after TCI + Vlan Eth
    data_after_vlan_ptr = tpid_ptr + sizeof(uint16_t) + (sizeof(netflow::protocols::VlanTag) - sizeof(uint16_t)); // Start of payload
    
    size_t vlan_header_total_size = sizeof(netflow::protocols::VlanTag); // TPID(2) + TCI(2) = 4 bytes for the actual tag
                                                                    // but our struct VlanTag is TCI + Ethertype.
                                                                    // The actual on-wire VLAN tag is 4 bytes.
                                                                    // Ethertype (TPID) + TCI + Encapsulated Ethertype.
                                                                    // No, the struct VlanTag is TCI + ethertype. Size 4 bytes.
                                                                    // The eth_hdr->ethertype is the TPID. This is followed by TCI and then the encapsulated ethertype.
    
    unsigned char* start_of_vlan_tag_proper = tpid_ptr + sizeof(uint16_t); // Start of TCI
    unsigned char* start_of_payload = start_of_vlan_tag_proper + (sizeof(netflow::protocols::VlanTag)); // This is where payload starts, after TCI and encapsulated ethertype

    size_t payload_len = current_length_ - (start_of_payload - head_data_ptr_);

    // Overwrite TPID field with encapsulated ethertype
    eth_hdr->ethertype = encapsulated_ethertype; // encapsulated_ethertype is already network order

    // Shift payload
    // Destination: where TCI started (right after the new eth_hdr->ethertype)
    // Source: start_of_payload
    std::memmove(tpid_ptr + sizeof(uint16_t), start_of_payload, payload_len);

    current_length_ -= (sizeof(netflow::protocols::VlanTag)); // We remove TCI + encapsulated ethertype (4 bytes)
    buffer_->set_data_len(current_length_);
    // update_checksums();
    return true;
}

void Packet::update_checksums() {
    // std::cout << "Packet::update_checksums() called - actual checksum logic not implemented." << std::endl;
    auto ipv4_hdr = ipv4();
    if (ipv4_hdr) {
        ipv4_hdr->header_checksum = 0;
        uint32_t sum = 0;
        uint16_t* words = reinterpret_cast<uint16_t*>(ipv4_hdr);
        size_t header_len_bytes = (ipv4_hdr->version_ihl & 0x0F) * 4;
        for (size_t i = 0; i < header_len_bytes / 2; ++i) {
            sum += ntohs(words[i]); 
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ipv4_hdr->header_checksum = htons(~static_cast<uint16_t>(sum));
    }
}
