#ifndef NETFLOW_PLUS_PLUS_SWITCHING_VLAN_MANAGER_HPP
#define NETFLOW_PLUS_PLUS_SWITCHING_VLAN_MANAGER_HPP

#include <cstdint>
#include <map>
#include <set>
#include <vector>
// Forward declare Packet from core namespace if needed for process_ingress/egress_packet
namespace netflow_plus_plus { namespace core { class Packet; } }

namespace netflow_plus_plus {
namespace switching {

enum class PortMode {
    ACCESS,
    TRUNK,
    HYBRID // Hybrid not fully detailed for now, acts like trunk mostly
};

struct VlanPortConfig {
    PortMode mode = PortMode::ACCESS;
    uint16_t native_vlan = 1;       // PVID for access mode, native VLAN for trunk
    std::set<uint16_t> allowed_vlans; // Relevant for TRUNK and HYBRID mode
    bool tag_native_traffic = false;  // For TRUNK mode, if native VLAN traffic should be tagged

    VlanPortConfig() {
        // By default, an access port allows its native VLAN.
        // For a trunk, allowed_vlans should be explicitly set.
        if (mode == PortMode::ACCESS) {
            allowed_vlans.insert(native_vlan);
        }
    }
};

class VlanManager {
public:
    VlanManager();

    void create_vlan(uint16_t vlan_id);
    void delete_vlan(uint16_t vlan_id);
    bool is_vlan_created(uint16_t vlan_id) const;
    std::set<uint16_t> get_configured_vlans() const;


    void configure_port(uint32_t port, const VlanPortConfig& config);
    VlanPortConfig get_port_vlan_config(uint32_t port) const;

    /**
     * @brief Determines if traffic for a given VLAN should be forwarded between two ports.
     * Placeholder: Currently always returns true if VLAN is created and allowed on both ports (simplified).
     * A full implementation would check STP state, VLAN membership, port states etc.
     * @param ingress_port The ingress port ID.
     * @param egress_port The egress port ID.
     * @param vlan_id The VLAN ID of the traffic.
     * @return True if forwarding is allowed, false otherwise.
     */
    bool should_forward(uint32_t ingress_port, uint32_t egress_port, uint16_t vlan_id);

    /**
     * @brief Processes a packet arriving on an ingress port according to VLAN rules.
     * E.g., for access ports, it might tag untagged traffic with the PVID.
     * For trunk ports, it checks if the VLAN tag is allowed.
     * Placeholder: Currently does nothing to the packet.
     * @param pkt The packet to process.
     * @param port The ingress port ID.
     */
    void process_ingress_packet(core::Packet& pkt, uint32_t port);

    /**
     * @brief Processes a packet before it leaves an egress port according to VLAN rules.
     * E.g., for access ports, it might strip the VLAN tag if it matches PVID.
     * For trunk ports, it might strip the tag if it's the native untagged VLAN.
     * Placeholder: Currently does nothing to the packet.
     * @param pkt The packet to process.
     * @param port The egress port ID.
     */
    void process_egress_packet(core::Packet& pkt, uint32_t port);


private:
    std::map<uint32_t, VlanPortConfig> port_vlan_configs_;
    std::set<uint16_t> configured_vlans_; // Set of all globally created VLAN IDs
};

} // namespace switching
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_SWITCHING_VLAN_MANAGER_HPP
