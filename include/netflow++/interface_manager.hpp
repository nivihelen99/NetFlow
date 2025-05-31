#ifndef NETFLOW_INTERFACE_MANAGER_HPP
#define NETFLOW_INTERFACE_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress and MacAddress
#include <cstdint>
#include <vector>
#include <map>
#include <functional>
#include <string>
#include <algorithm>
#include <optional>
#include <mutex> // Required for std::mutex

namespace netflow {

struct InterfaceIpConfig {
    IpAddress address;
    IpAddress subnet_mask;

    InterfaceIpConfig(IpAddress addr, IpAddress mask) : address(addr), subnet_mask(mask) {}
    InterfaceIpConfig() : address(0), subnet_mask(0) {}
};

class InterfaceManager {
public:
    struct PortStats {
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
        uint64_t rx_drops = 0;
        uint64_t tx_drops = 0;
        PortStats() = default;
    };

    struct PortConfig {
        bool admin_up = false;
        uint32_t speed_mbps = 1000;
        bool full_duplex = true;
        bool auto_negotiation = true;
        uint32_t mtu = 1500;
        MacAddress mac_address;
        std::vector<InterfaceIpConfig> ip_configurations;
        PortConfig() : mac_address() {}
    };

    InterfaceManager();

    void add_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask);
    void remove_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask);
    std::vector<InterfaceIpConfig> get_interface_ip_configs(uint32_t interface_id) const;
    bool is_my_ip(const IpAddress& ip) const;
    std::optional<uint32_t> find_interface_for_ip(const IpAddress& ip) const;
    std::optional<MacAddress> get_mac_for_ip(const IpAddress& ip) const;
    bool is_ip_local_to_interface(uint32_t interface_id, const IpAddress& ip) const;
    std::optional<MacAddress> get_interface_mac(uint32_t interface_id) const;
    std::optional<IpAddress> get_interface_ip(uint32_t interface_id) const;

    void configure_port(uint32_t port_id, const PortConfig& config);
    std::optional<PortConfig> get_port_config(uint32_t port_id) const;
    PortStats get_port_stats(uint32_t port_id) const;
    void clear_port_stats(uint32_t port_id);
    bool is_port_admin_up(uint32_t port_id) const;
    bool is_port_link_up(uint32_t port_id) const;

    void on_link_up(std::function<void(uint32_t port_id)> callback);
    void on_link_down(std::function<void(uint32_t port_id)> callback);
    void simulate_port_link_up(uint32_t port_id);
    void simulate_port_link_down(uint32_t port_id);

    std::vector<uint32_t> get_all_interface_ids() const;
    bool is_port_valid(uint32_t port_id) const;
    std::vector<uint32_t> get_all_l3_interface_ids() const;
    std::map<uint32_t, PortConfig> get_all_port_configs() const;

public:
    void _increment_rx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);
    void _increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);

private:
    std::map<uint32_t, PortConfig> port_configs_;
    std::map<uint32_t, PortStats> port_stats_;
    mutable std::mutex port_data_mutex_; // Mutex for port_configs_ and port_stats_

    std::map<uint32_t, bool> simulated_link_state_;
    std::vector<std::function<void(uint32_t port_id)>> link_up_callbacks_;
    std::vector<std::function<void(uint32_t port_id)>> link_down_callbacks_;
};

} // namespace netflow

#endif // NETFLOW_INTERFACE_MANAGER_HPP
