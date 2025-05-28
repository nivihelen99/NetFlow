#ifndef NETFLOW_SWITCH_VLANMANAGER_H
#define NETFLOW_SWITCH_VLANMANAGER_H

#include "netflow/packet/Packet.h" // For Packet object
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex> // For thread safety

// Maximum VLAN ID (12 bits, 0 and 4095 are reserved)
const uint16_t MAX_VLAN_ID = 4094;
const uint16_t DEFAULT_VLAN_ID = 1;

class VlanManager {
public:
    // PortType: Defines how a port handles VLAN tags
    enum class PortType {
        ACCESS,     // Port is an access port, carries untagged traffic for a single VLAN
        TRUNK,      // Port is a trunk port, carries tagged traffic for multiple VLANs
        NATIVE_VLAN // Port is a trunk port but has a native VLAN for untagged traffic
    };

    struct PortConfig {
        PortType type = PortType::ACCESS;
        uint16_t access_vlan_id = DEFAULT_VLAN_ID;   // For ACCESS mode: the VLAN ID assigned to untagged traffic
        uint16_t native_vlan_id = DEFAULT_VLAN_ID;  // For TRUNK with NATIVE_VLAN: VLAN for untagged/priority-tagged ingress
        std::unordered_set<uint16_t> allowed_vlans; // For TRUNK mode: set of allowed VLAN IDs on this trunk. If empty, all VLANs allowed.
        bool learning_disabled = false; // Whether MAC learning is disabled on this port/VLAN context

        PortConfig() {
            // By default, if it's a trunk, allow all VLANs unless specified.
            // For an access port, allowed_vlans is implicitly just the access_vlan_id.
        }
    };

    explicit VlanManager();

    // Configure a port's VLAN settings.
    // port_id: The physical or logical port identifier.
    bool configure_port(uint16_t port_id, const PortConfig& config);
    const PortConfig* get_port_config(uint16_t port_id) const;

    // Ingress Processing: Modifies the packet based on port's VLAN config.
    // - Access port: If untagged, tags with access_vlan_id. If tagged and matches access_vlan_id, allows. Else drops.
    // - Trunk port: If tagged and VLAN allowed, allows. If untagged and port has native VLAN, tags with native_vlan_id. Else drops.
    // Returns the effective VLAN ID for the packet after ingress processing.
    // Returns 0 or a special value if the packet should be dropped.
    uint16_t process_ingress(Packet& pkt, uint16_t port_id);
    static const uint16_t VLAN_DROP = 0;


    // Egress Processing: Modifies the packet for sending out a port.
    // - Access port: If packet's VLAN matches access_vlan_id, removes tag. Else drops.
    // - Trunk port: If packet's VLAN is native_vlan_id, removes tag. If packet's VLAN is in allowed_vlans, keeps tag. Else drops.
    // Returns true if the packet should be forwarded out this port, false if dropped.
    // pkt_vlan_id: The effective VLAN ID of the packet (e.g., from FDB lookup or ingress processing).
    bool process_egress(Packet& pkt, uint16_t port_id, uint16_t pkt_vlan_id);

    // Forwarding Decision: Check if a packet with a given VLAN ID should be forwarded out of a specific port.
    // This is a simpler check, often used before full egress processing.
    bool should_forward(uint16_t port_id, uint16_t pkt_vlan_id) const;

    // Membership checks
    bool is_vlan_member(uint16_t port_id, uint16_t vlan_id) const;
    bool add_vlan_member(uint16_t port_id, uint16_t vlan_id); // Makes port member of vlan (for trunk)
    bool remove_vlan_member(uint16_t port_id, uint16_t vlan_id); // Removes vlan from port (for trunk)

    // Create/delete VLANs globally
    bool create_vlan(uint16_t vlan_id, const std::string& name = "");
    // bool delete_vlan(uint16_t vlan_id);
    // std::unordered_set<uint16_t> get_all_vlans() const;

    // Port configuration overload
    bool configure_port(uint16_t port_id, PortType type, uint16_t vlan_id);

private:
    // std::unordered_map<uint16_t, std::string> vlan_names_; // VLAN names storage - not added in this step
    std::unordered_map<uint16_t, PortConfig> port_configurations_;
    // std::unordered_set<uint16_t> known_vlans_; // Optional: to keep track of all configured VLANs
    mutable std::mutex vlan_mutex_; // To protect access to configurations
};

#endif // NETFLOW_SWITCH_VLANMANAGER_H
