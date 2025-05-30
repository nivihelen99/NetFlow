#ifndef NETFLOW_PLUS_PLUS_PROTO_VLAN_HPP
#define NETFLOW_PLUS_PLUS_PROTO_VLAN_HPP

#include <cstdint>
// #include <arpa/inet.h> // For ntohs/htons if needed

namespace netflow_plus_plus {
namespace proto {

// Standard TPID for 802.1Q VLAN tags
constexpr uint16_t VLAN_TPID = 0x8100;

/**
 * @brief Represents an 802.1Q VLAN Tag.
 *
 * The structure is:
 * TPID (Tag Protocol Identifier): 2 bytes (e.g., 0x8100)
 * TCI (Tag Control Information): 2 bytes
 *   - PCP (Priority Code Point): 3 bits
 *   - DEI (Drop Eligible Indicator): 1 bit
 *   - VID (VLAN Identifier): 12 bits
 */
#pragma pack(push, 1) // Ensure structure is packed
struct VlanTag {
    uint16_t tpid; // Tag Protocol Identifier (usually 0x8100). Network byte order.
    uint16_t tci;  // Tag Control Information (PCP, DEI, VID). Network byte order.

    /**
     * @brief Gets the Priority Code Point (PCP) from TCI.
     * @return PCP value (0-7).
     */
    uint8_t get_priority() const {
        // return (ntohs(tci) >> 13) & 0x07;
        return (tci >> 13) & 0x07; // Assuming TCI is already host byte order for internal logic
    }

    /**
     * @brief Gets the Drop Eligible Indicator (DEI) from TCI.
     * @return DEI value (0 or 1).
     */
    uint8_t get_dei() const {
        // return (ntohs(tci) >> 12) & 0x01;
        return (tci >> 12) & 0x01; // Assuming TCI is already host byte order
    }

    /**
     * @brief Gets the VLAN Identifier (VID) from TCI.
     * @return VID value (0-4095).
     */
    uint16_t get_vlan_id() const {
        // return ntohs(tci) & 0x0FFF;
        return tci & 0x0FFF; // Assuming TCI is already host byte order
    }

    /**
     * @brief Sets the TCI based on PCP, DEI, and VID.
     * @param priority PCP value (0-7).
     * @param dei DEI value (0 or 1).
     * @param vlan_id VID value (0-4095).
     */
    void set_tci(uint8_t priority, uint8_t dei, uint16_t vlan_id) {
        uint16_t new_tci_host_order = ((static_cast<uint16_t>(priority) & 0x07) << 13) |
                                      ((static_cast<uint16_t>(dei) & 0x01) << 12) |
                                      (vlan_id & 0x0FFF);
        // tci = htons(new_tci_host_order);
        tci = new_tci_host_order; // Store in host byte order for now
    }
};
#pragma pack(pop) // Restore default packing


/**
 * @brief Represents the VLAN header fields that appear after the MAC addresses
 *        when a frame is VLAN-tagged. This typically includes one or more VlanTags
 *        followed by the actual EtherType of the payload.
 *
 * Note: A packet can have multiple VLAN tags (QinQ). This header represents
 * the first VLAN tag. The `Packet::vlan()` method would point to this structure.
 * The `ether_type` field here is the "inner" EtherType, specifying the protocol
 * encapsulated within this VLAN tag.
 */
#pragma pack(push, 1)
struct VlanHeader {
    VlanTag tag;
    uint16_t original_ether_type; // The EtherType of the payload (e.g., IPv4, IPv6). Network byte order.

    // Helper methods can delegate to the VlanTag or provide combined info

    uint16_t get_tpid() const {
        // return ntohs(tag.tpid);
        return tag.tpid; // Assuming host byte order
    }

    uint8_t get_priority() const {
        return tag.get_priority();
    }

    uint8_t get_dei() const {
        return tag.get_dei();
    }

    uint16_t get_vlan_id() const {
        return tag.get_vlan_id();
    }

    uint16_t get_original_ether_type() const {
        // return ntohs(original_ether_type);
        return original_ether_type; // Assuming host byte order
    }

    void set_vlan_details(uint16_t v_id, uint8_t prio = 0, uint8_t dei_val = 0) {
        tag.tpid = VLAN_TPID; // Or htons(VLAN_TPID)
        tag.set_tci(prio, dei_val, v_id);
    }
};
#pragma pack(pop)

} // namespace proto
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_PROTO_VLAN_HPP
