#ifndef NETFLOW_PLUS_PLUS_PORT_INTERFACE_MANAGER_HPP
#define NETFLOW_PLUS_PLUS_PORT_INTERFACE_MANAGER_HPP

#include <cstdint>
#include <map>
#include <functional> // For std::function
#include <string> // For potential future use (e.g., port names)

namespace netflow_plus_plus {
namespace port {

struct PortStats {
    uint64_t rx_packets = 0;
    uint64_t tx_packets = 0;
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
    uint64_t rx_errors = 0;
    uint64_t tx_errors = 0;
    uint64_t rx_drops = 0;
    uint64_t tx_drops = 0;
};

struct PortConfig {
    bool admin_up = false;
    uint32_t speed_mbps = 0;  // 10, 100, 1000, 10000, etc.
    bool full_duplex = false;
    bool auto_negotiation = true;
    uint32_t mtu = 1500;
    // std::string description; // Potential future addition
};

class InterfaceManager {
public:
    InterfaceManager();

    void configure_port(uint32_t port, const PortConfig& config);
    PortConfig get_port_config(uint32_t port) const;

    PortStats get_port_stats(uint32_t port) const;
    void clear_port_stats(uint32_t port);

    bool is_port_up(uint32_t port) const; // Checks admin_up primarily
    void set_port_admin_state(uint32_t port, bool up);

    // Placeholders for callback mechanisms
    void on_link_up(std::function<void(uint32_t port_id)> callback);
    void on_link_down(std::function<void(uint32_t port_id)> callback);

    // Utility to simulate a link event for testing callbacks
    void simulate_link_up(uint32_t port_id);
    void simulate_link_down(uint32_t port_id);


private:
    std::map<uint32_t, PortConfig> port_configs_;
    std::map<uint32_t, PortStats> port_stats_;

    // Callbacks
    std::function<void(uint32_t)> link_up_callback_;
    std::function<void(uint32_t)> link_down_callback_;

    // Note: In a real system, operational status (is_port_oper_up) would also be tracked,
    // influenced by physical link state, not just admin_up.
};

} // namespace port
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_PORT_INTERFACE_MANAGER_HPP
