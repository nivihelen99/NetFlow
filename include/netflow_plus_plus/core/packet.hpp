#ifndef NETFLOW_PLUS_PLUS_CORE_PACKET_HPP
#define NETFLOW_PLUS_PLUS_CORE_PACKET_HPP

#include "netflow_plus_plus/core/packet_buffer.hpp"
#include "netflow_plus_plus/core/types.hpp"        // For MacAddress
#include "netflow_plus_plus/proto/ethernet.hpp"    // For EthernetHeader
#include "netflow_plus_plus/proto/vlan.hpp"        // For VlanHeader
#include "netflow_plus_plus/proto/placeholders.hpp" // For other dummy headers
#include <memory> // For std::shared_ptr
#include <cstring> // For memcpy
#include <vector>  // For std::vector in push_vlan/pop_vlan
#include <algorithm> // For std::copy
#include <arpa/inet.h> // For htons/ntohs

namespace netflow_plus_plus {
namespace core {

/**
 * @brief Represents a network packet.
 *
 * This class provides an interface to access and manipulate packet data
 * stored in a PacketBuffer. It offers methods to retrieve various protocol
 * headers and will later include packet manipulation functionalities.
 */
class Packet {
public:
    /**
     * @brief Constructs a Packet.
     *
     * @param buffer A shared pointer to the PacketBuffer that holds the packet data.
     *               The Packet class will share ownership of this buffer.
     */
    explicit Packet(std::shared_ptr<PacketBuffer> buffer)
        : buffer_(buffer) {}

    /**
     * @brief Generic method to access a protocol header.
     *
     * This template method attempts to cast a part of the packet data to the specified
     * HeaderType. The actual implementation will require knowledge of header offsets
     * and packet structure.
     *
     * @tparam HeaderType The type of the header to retrieve (e.g., EthernetHeader).
     * @return Pointer to the header if found and valid, nullptr otherwise.
     *         Currently, it's a placeholder and returns nullptr.
     */
    template<typename HeaderType>
    HeaderType* get_header(size_t offset = 0) const {
        if (!buffer_ || buffer_->get_size() < (offset + sizeof(HeaderType))) {
            return nullptr;
        }
        return reinterpret_cast<HeaderType*>(buffer_->get_data() + offset);
    }

    /**
     * @brief Gets a pointer to the Ethernet header.
     * Assumes the packet data starts with an Ethernet header.
     * @return Pointer to EthernetHeader or nullptr if not present/applicable or buffer too small.
     */
    proto::EthernetHeader* ethernet() const {
        if (!buffer_ || buffer_->get_size() < sizeof(proto::EthernetHeader)) {
            return nullptr;
        }
        return reinterpret_cast<proto::EthernetHeader*>(buffer_->get_data());
    }

    /**
     * @brief Gets the source MAC address from the Ethernet header.
     * @return MacAddress object. Returns an all-zero MAC if header is not accessible.
     */
    core::MacAddress src_mac() const {
        proto::EthernetHeader* eth_hdr = ethernet();
        if (eth_hdr) {
            return eth_hdr->source_mac;
        }
        return core::MacAddress(); // Return an empty/default MAC address
    }

    /**
     * @brief Gets the destination MAC address from the Ethernet header.
     * @return MacAddress object. Returns an all-zero MAC if header is not accessible.
     */
    core::MacAddress dst_mac() const {
        proto::EthernetHeader* eth_hdr = ethernet();
        if (eth_hdr) {
            return eth_hdr->destination_mac;
        }
        return core::MacAddress(); // Return an empty/default MAC address
    }

    /**
     * @brief Sets the destination MAC address in the Ethernet header.
     * Does nothing if the Ethernet header is not accessible.
     * @param mac The new destination MAC address.
     */
    void set_dst_mac(const core::MacAddress& mac) {
        proto::EthernetHeader* eth_hdr = ethernet();
        if (eth_hdr) {
            eth_hdr->destination_mac = mac;
        }
    }

    /**
     * @brief Sets the source MAC address in the Ethernet header.
     * Does nothing if the Ethernet header is not accessible.
     * @param mac The new source MAC address.
     */
    void set_src_mac(const core::MacAddress& mac) {
        proto::EthernetHeader* eth_hdr = ethernet();
        if (eth_hdr) {
            eth_hdr->source_mac = mac;
        }
    }

    /**
     * @brief Gets a pointer to the VLAN header.
     * @return Pointer to VlanHeader or nullptr if not present/applicable.
     *         Currently, it's a placeholder.
     */
    proto::VlanHeader* vlan(int tag_index = 0) const {
        proto::EthernetHeader* eth = ethernet();
        if (!eth) return nullptr;

        size_t offset = sizeof(proto::EthernetHeader);
        uint16_t current_ethertype = ntohs(eth->ether_type);

        for (int i = 0; i <= tag_index; ++i) {
            if (current_ethertype == proto::ETHERTYPE_VLAN) {
                if (buffer_->get_size() < offset + sizeof(proto::VlanHeader)) {
                    return nullptr; // Not enough data for this VLAN header
                }
                proto::VlanHeader* vlan_hdr = reinterpret_cast<proto::VlanHeader*>(buffer_->get_data() + offset);
                if (i == tag_index) {
                    return vlan_hdr;
                }
                current_ethertype = ntohs(vlan_hdr->original_ether_type);
                offset += sizeof(proto::VlanHeader);
            } else {
                return nullptr; // Not a VLAN tag or not the Nth tag
            }
        }
        return nullptr;
    }

    bool has_vlan() const {
        proto::EthernetHeader* eth = ethernet();
        if (eth) {
            return ntohs(eth->ether_type) == proto::ETHERTYPE_VLAN;
        }
        return false;
    }

    uint16_t vlan_id(int tag_index = 0) const {
        proto::VlanHeader* vlan_hdr = vlan(tag_index);
        if (vlan_hdr) {
            return ntohs(vlan_hdr->tag.tci) & 0x0FFF;
        }
        return 0; // Or throw an exception, or return optional<uint16_t>
    }

    uint8_t vlan_priority(int tag_index = 0) const {
        proto::VlanHeader* vlan_hdr = vlan(tag_index);
        if (vlan_hdr) {
            return (ntohs(vlan_hdr->tag.tci) >> 13) & 0x07;
        }
        return 0; // Or throw an exception
    }

    // push_vlan and pop_vlan are complex due to buffer manipulation.
    // These are simplified placeholders. A full implementation needs robust buffer resizing.
    // Assumes the PacketBuffer is managed by std::shared_ptr and can be replaced.

    void push_vlan(uint16_t v_id, uint8_t priority = 0, uint8_t dei = 0) {
        if (!buffer_ || !ethernet()) return; // Cannot add VLAN to an invalid packet

        size_t current_size = buffer_->get_size();
        size_t eth_header_size = sizeof(proto::EthernetHeader);
        size_t vlan_header_size = sizeof(proto::VlanHeader);

        // New buffer size
        size_t new_size = current_size + vlan_header_size;
        std::vector<unsigned char> new_data_vec(new_size);

        unsigned char* old_data = buffer_->get_data();

        // Copy Ethernet header
        std::memcpy(new_data_vec.data(), old_data, eth_header_size);

        // Create and insert VLAN header
        proto::VlanHeader* new_vlan_hdr = reinterpret_cast<proto::VlanHeader*>(new_data_vec.data() + eth_header_size);
        new_vlan_hdr->tag.tpid = htons(proto::VLAN_TPID);
        new_vlan_hdr->tag.tci = htons(((priority & 0x07) << 13) | ((dei & 0x01) << 12) | (v_id & 0x0FFF));

        // Original EtherType from Ethernet header becomes VLAN's original_ether_type
        proto::EthernetHeader* orig_eth_hdr = reinterpret_cast<proto::EthernetHeader*>(new_data_vec.data());
        new_vlan_hdr->original_ether_type = orig_eth_hdr->ether_type; // Already in network byte order

        // Update Ethernet header's EtherType to indicate VLAN
        orig_eth_hdr->ether_type = htons(proto::ETHERTYPE_VLAN);

        // Copy the rest of the packet
        if (current_size > eth_header_size) {
            std::memcpy(new_data_vec.data() + eth_header_size + vlan_header_size,
                        old_data + eth_header_size,
                        current_size - eth_header_size);
        }
        
        // Replace the old buffer with the new one
        // This assumes PacketBuffer can be constructed from owned data
        buffer_ = std::make_shared<PacketBuffer>(new_data_vec.data(), new_data_vec.size());
    }

    void pop_vlan() {
        if (!has_vlan() || !buffer_) return;

        proto::EthernetHeader* eth_hdr = ethernet(); // Should exist if has_vlan is true
        proto::VlanHeader* vlan_hdr = vlan();       // Gets the first VLAN tag
        if (!eth_hdr || !vlan_hdr) return;          // Should not happen if has_vlan is true

        size_t current_size = buffer_->get_size();
        size_t eth_header_size = sizeof(proto::EthernetHeader);
        size_t vlan_header_size = sizeof(proto::VlanHeader);

        if (current_size < eth_header_size + vlan_header_size) return; // Should not happen

        // New buffer size
        size_t new_size = current_size - vlan_header_size;
        std::vector<unsigned char> new_data_vec(new_size);
        unsigned char* old_data = buffer_->get_data();

        // Copy Ethernet header part
        std::memcpy(new_data_vec.data(), old_data, eth_header_size);

        // Restore original EtherType from VLAN header to Ethernet header
        proto::EthernetHeader* new_eth_hdr = reinterpret_cast<proto::EthernetHeader*>(new_data_vec.data());
        new_eth_hdr->ether_type = vlan_hdr->original_ether_type; // Already in network byte order

        // Copy the rest of the packet (payload after VLAN header)
        size_t payload_offset_in_old = eth_header_size + vlan_header_size;
        if (current_size > payload_offset_in_old) {
            std::memcpy(new_data_vec.data() + eth_header_size,
                        old_data + payload_offset_in_old,
                        current_size - payload_offset_in_old);
        }
        
        // Replace the old buffer
        buffer_ = std::make_shared<PacketBuffer>(new_data_vec.data(), new_data_vec.size());
    }


    /**
     * @brief Gets a pointer to the IPv4 header.
     * @return Pointer to IPv4Header or nullptr if not present/applicable.
     *         Currently, it's a placeholder.
     */
    proto::IPv4Header* ipv4() const {
        // Placeholder:
        // return get_header<proto::IPv4Header>();
        return nullptr;
    }

    /**
     * @brief Gets a pointer to the IPv6 header.
     * @return Pointer to IPv6Header or nullptr if not present/applicable.
     *         Currently, it's a placeholder.
     */
    proto::IPv6Header* ipv6() const {
        // Placeholder:
        // return get_header<proto::IPv6Header>();
        return nullptr;
    }

    /**
     * @brief Gets a pointer to the TCP header.
     * @return Pointer to TcpHeader or nullptr if not present/applicable.
     *         Currently, it's a placeholder.
     */
    proto::TcpHeader* tcp() const {
        // Placeholder:
        // return get_header<proto::TcpHeader>();
        return nullptr;
    }

    /**
     * @brief Gets a pointer to the UDP header.
     * @return Pointer to UdpHeader or nullptr if not present/applicable.
     *         Currently, it's a placeholder.
     */
    proto::UdpHeader* udp() const {
        // Placeholder:
        // return get_header<proto::UdpHeader>();
        return nullptr;
    }

    /**
     * @brief Updates checksums for relevant protocols (e.g., IP, TCP, UDP).
     *
     * Placeholder for checksum calculation and update logic.
     */
    void update_checksums() {
        // Implementation will involve recalculating and writing checksums
        // for IP, TCP, UDP headers if they are modified.
    }

    /**
     * @brief Gets the underlying PacketBuffer.
     * @return A shared pointer to the PacketBuffer.
     */
    std::shared_ptr<PacketBuffer> get_buffer() const {
        return buffer_;
    }

private:
    std::shared_ptr<PacketBuffer> buffer_; // Shared ownership of the packet data buffer
};

} // namespace core
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_CORE_PACKET_HPP
