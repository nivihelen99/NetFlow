#ifndef NETFLOW_VLAN_MANAGER_HPP
#define NETFLOW_VLAN_MANAGER_HPP

#include "packet.hpp" // For netflow::Packet and its associated types like VlanHeader

#include <cstdint>   // For uint16_t, uint32_t
#include <set>       // For std::set
#include <map>       // For std::map
#include <optional>  // For std::optional
#include <stdexcept> // For std::invalid_argument (potentially in .cpp)

namespace netflow {

enum class PortType {
    ACCESS,
    TRUNK,
    HYBRID
};

enum class PacketAction {
    FORWARD,
    DROP,
    CONSUME
};

struct VlanManagerConfig {
    // Global VLAN settings can go here.
};

class VlanManager {
public:
    struct PortConfig {
        PortType type = PortType::ACCESS;
        uint16_t native_vlan = 1;
        std::set<uint16_t> allowed_vlans;
        bool tag_native = false;

        PortConfig() {
            if (type == PortType::ACCESS) {
                allowed_vlans.insert(native_vlan);
            }
        }
    };

    explicit VlanManager(const VlanManagerConfig& global_config = VlanManagerConfig());

    void configure_port(uint32_t port_id, const PortConfig& config);
    std::optional<PortConfig> get_port_config(uint32_t port_id) const;

    bool should_forward(uint32_t ingress_port_id, uint32_t egress_port_id, uint16_t vlan_id) const;

    PacketAction process_ingress(Packet& pkt, uint32_t port_id);
    void process_egress(Packet& pkt, uint32_t port_id);

private:
    std::map<uint32_t, PortConfig> port_configs_;
    VlanManagerConfig global_config_;
};

} // namespace netflow

#endif // NETFLOW_VLAN_MANAGER_HPP
